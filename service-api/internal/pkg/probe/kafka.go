package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	productKafka           = "kafka"
	kafkaAPIKeyAPIVersions = 18
	kafkaClientID          = "uv-scanner"
	kafkaMaxResponseSize   = 1 << 20
)

func init() {
	Register(probeKafka, 9092)
}

// kafkaAPIVersion is one entry in the ApiVersions response.
type kafkaAPIVersion struct {
	APIKey int16 `json:"api_key"`
	MinVer int16 `json:"min_version"`
	MaxVer int16 `json:"max_version"`
}

// kafkaFacts is what probeKafka returns in FingerprintResult.RawJSON.
type kafkaFacts struct {
	ErrorCode    int16             `json:"error_code"`
	APIVersions  []kafkaAPIVersion `json:"api_versions"`
	VersionRange string            `json:"version_range,omitempty"`
}

// probeKafka issues an ApiVersions request (v1) and translates the max
// supported version into a human-readable broker version range.
func probeKafka(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial Kafka: %w", err)
	}

	defer func() { _ = conn.Close() }()

	req, err := buildKafkaAPIVersionsRequest(1)
	if err != nil {
		return nil, fmt.Errorf("can't build Kafka request: %w", err)
	}

	if _, err = conn.Write(req); err != nil {
		return nil, fmt.Errorf("can't write Kafka request: %w", err)
	}

	facts, err := readKafkaAPIVersionsResponse(conn)
	if err != nil {
		return nil, err
	}

	authRequired := facts.ErrorCode != 0

	fp := &FingerprintResult{
		Product:      productKafka,
		Version:      facts.VersionRange,
		AuthRequired: &authRequired,
		Anonymous:    !authRequired,
		RawJSON:      mustMarshalJSON(facts),
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Fingerprint: fp,
	}, nil
}

// buildKafkaAPIVersionsRequest builds an ApiVersions v0 request frame.
func buildKafkaAPIVersionsRequest(correlationID int32) ([]byte, error) {
	body := &bytes.Buffer{}

	if err := binary.Write(body, binary.BigEndian, int16(kafkaAPIKeyAPIVersions)); err != nil {
		return nil, err
	}

	if err := binary.Write(body, binary.BigEndian, int16(0)); err != nil {
		return nil, err
	}

	if err := binary.Write(body, binary.BigEndian, correlationID); err != nil {
		return nil, err
	}

	if err := binary.Write(body, binary.BigEndian, int16(len(kafkaClientID))); err != nil {
		return nil, err
	}

	body.WriteString(kafkaClientID)

	out := &bytes.Buffer{}

	if err := binary.Write(out, binary.BigEndian, int32(body.Len())); err != nil {
		return nil, err
	}

	out.Write(body.Bytes())

	return out.Bytes(), nil
}

// readKafkaAPIVersionsResponse parses the ApiVersions response and computes
// VersionRange in one pass.
func readKafkaAPIVersionsResponse(r io.Reader) (*kafkaFacts, error) {
	var size int32

	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return nil, fmt.Errorf("can't read Kafka response size: %w", err)
	}

	if size <= 0 || size > kafkaMaxResponseSize {
		return nil, fmt.Errorf("kafka response size out of range: %d", size)
	}

	payload := make([]byte, size)

	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("can't read Kafka response payload: %w", err)
	}

	reader := bytes.NewReader(payload)

	var correlationID int32

	if err := binary.Read(reader, binary.BigEndian, &correlationID); err != nil {
		return nil, fmt.Errorf("can't read Kafka correlation ID: %w", err)
	}

	var errorCode int16

	if err := binary.Read(reader, binary.BigEndian, &errorCode); err != nil {
		return nil, fmt.Errorf("can't read Kafka error code: %w", err)
	}

	var apiCount int32

	if err := binary.Read(reader, binary.BigEndian, &apiCount); err != nil {
		return nil, fmt.Errorf("can't read Kafka API count: %w", err)
	}

	if apiCount < 0 || apiCount > 1024 {
		return nil, fmt.Errorf("kafka API count out of range: %d", apiCount)
	}

	apis := make([]kafkaAPIVersion, 0, apiCount)

	for range int(apiCount) {
		var entry kafkaAPIVersion

		if err := binary.Read(reader, binary.BigEndian, &entry.APIKey); err != nil {
			return nil, fmt.Errorf("can't read Kafka API key: %w", err)
		}

		if err := binary.Read(reader, binary.BigEndian, &entry.MinVer); err != nil {
			return nil, fmt.Errorf("can't read Kafka API min version: %w", err)
		}

		if err := binary.Read(reader, binary.BigEndian, &entry.MaxVer); err != nil {
			return nil, fmt.Errorf("can't read Kafka API max version: %w", err)
		}

		apis = append(apis, entry)
	}

	return &kafkaFacts{
		ErrorCode:    errorCode,
		APIVersions:  apis,
		VersionRange: kafkaVersionRange(apis),
	}, nil
}

// kafkaVersionRange maps the max version of api_key=18 (ApiVersions) to a
// human-readable broker version range.
func kafkaVersionRange(apis []kafkaAPIVersion) string {
	for _, a := range apis {
		if a.APIKey != kafkaAPIKeyAPIVersions {
			continue
		}

		switch {
		case a.MaxVer >= 3:
			return ">=2.4"
		case a.MaxVer == 2:
			return "1.0-2.3"
		case a.MaxVer == 1:
			return "0.10.2-0.11"
		case a.MaxVer == 0:
			return "0.10.0-0.10.1"
		}
	}

	return ""
}
