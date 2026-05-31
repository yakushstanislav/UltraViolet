package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"go.mongodb.org/mongo-driver/v2/bson"
)

const productMongoDB = "mongodb"

func init() {
	Register(probeMongoDB, 27017)
}

// probeMongoDB issues isMaster + buildInfo commands and packages the result
// into a fingerprint. Anonymous access is inferred from a successful
// buildInfo response.
func probeMongoDB(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial MongoDB: %w", err)
	}

	defer func() { _ = conn.Close() }()

	isMaster, helloErr := mongoSimpleQuery(conn, "admin.$cmd", bson.M{"isMaster": 1})
	buildInfo, buildErr := mongoSimpleQuery(conn, "admin.$cmd", bson.M{"buildInfo": 1})

	if helloErr != nil && buildErr != nil {
		return nil, fmt.Errorf("can't query MongoDB handshake: %w", helloErr)
	}

	fp := &FingerprintResult{Product: productMongoDB}

	if buildErr == nil {
		if version, ok := buildInfo["version"].(string); ok {
			fp.Version = version
		}

		fp.Anonymous = true
		noAuth := false
		fp.AuthRequired = &noAuth
	}

	if isMaster != nil {
		if v, ok := isMaster["ismaster"].(bool); ok && v {
			fp.ClusterRole = "primary"
		} else {
			fp.ClusterRole = "standalone"
		}
	}

	if fp.AuthRequired == nil {
		authRequired := true
		fp.AuthRequired = &authRequired
	}

	fp.RawJSON = mustMarshalJSON(map[string]any{
		"is_master":  isMaster,
		"build_info": buildInfo,
	})

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Fingerprint: fp,
	}, nil
}

// mongoSimpleQuery sends an OP_QUERY for a single document command.
func mongoSimpleQuery(conn net.Conn, collection string, doc bson.M) (map[string]any, error) {
	query, err := bson.Marshal(doc)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(nil)
	_ = binary.Write(buf, binary.LittleEndian, int32(0))
	_ = binary.Write(buf, binary.LittleEndian, int32(1))
	_ = binary.Write(buf, binary.LittleEndian, int32(0))
	_ = binary.Write(buf, binary.LittleEndian, int32(2004))
	_ = binary.Write(buf, binary.LittleEndian, int32(0))
	_, _ = buf.WriteString(collection)
	_ = buf.WriteByte(0)
	_ = binary.Write(buf, binary.LittleEndian, int32(0))
	_ = binary.Write(buf, binary.LittleEndian, int32(1))
	_, _ = buf.Write(query)

	body := buf.Bytes()
	binary.LittleEndian.PutUint32(body[:4], uint32(len(body)))

	if _, err = conn.Write(body); err != nil {
		return nil, err
	}

	hdr := make([]byte, 16)
	if _, err = conn.Read(hdr); err != nil {
		return nil, err
	}

	msgLen := int(binary.LittleEndian.Uint32(hdr[:4]))
	if msgLen < 36 || msgLen > 1<<20 {
		return nil, errors.New("MongoDB response too large")
	}

	payload := make([]byte, msgLen-16)
	if _, err = conn.Read(payload); err != nil {
		return nil, err
	}

	if len(payload) < 20 {
		return nil, errors.New("MongoDB payload too short")
	}

	var out map[string]any
	if err = bson.Unmarshal(payload[20:], &out); err != nil {
		return nil, err
	}

	return out, nil
}
