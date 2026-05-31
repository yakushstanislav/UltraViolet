package probe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const productHL7MLLP = "hl7_mllp"

func init() {
	// 2575 is the IANA-assigned MLLP port. 5000 collides with probeHTTP
	// so we route HL7 hits there via derived.go. 6661/6662 are claimed
	// by Mirth Connect default deployments and ROS workers respectively;
	// only 2575 stays on our books.
	Register(probeHL7MLLP, 2575)
}

// probeHL7MLLP sends an HL7 v2 query (QRY^A19) framed by Minimal Lower
// Layer Protocol delimiters (0x0B header, 0x1C terminator) and inspects
// the reply for an MSH ACK segment. Even when the listener returns an
// error ACK (AE / AR), the message still proves HL7-MLLP is up.
func probeHL7MLLP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	timestamp := time.Now().UTC().Format("20060102150405")

	msg := fmt.Sprintf("MSH|^~\\&|UV|UV|RECV|RECV|%s||QRY^A19|Q001|P|2.5\rQRD|%s|R|I|Q001|||1^RD|||PID\r",
		timestamp, timestamp)

	frame := make([]byte, 0, len(msg)+3)
	frame = append(frame, 0x0B)
	frame = append(frame, msg...)
	frame = append(frame, 0x1C, 0x0D)

	if _, writeErr := conn.Write(frame); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 8192)

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}

	reply := string(buf[:n])

	stripped := strings.TrimLeft(reply, "\x0B")
	if idx := strings.IndexByte(stripped, 0x1C); idx >= 0 {
		stripped = stripped[:idx]
	}

	if !strings.HasPrefix(stripped, "MSH|") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: reply}, nil
	}

	sendingApp, sendingFacility, ackCode := parseHL7Header(stripped)

	product := productHL7MLLP

	if hint := hl7VendorHint(sendingApp, sendingFacility); hint != "" {
		product = hint
	}

	fp := &FingerprintResult{
		Product: product,
		Edition: sendingApp,
		RawJSON: mustMarshalJSON(map[string]any{
			"sending_application": sendingApp,
			"sending_facility":    sendingFacility,
			"ack_code":            ackCode,
			"snippet":             firstSegment(stripped),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    product,
		Banner:      firstSegment(stripped),
		Fingerprint: fp,
	}, nil
}

// parseHL7Header extracts Sending Application (MSH-3), Sending Facility
// (MSH-4) and (for ACK messages) the MSA-1 ack code. All optional.
func parseHL7Header(msg string) (string, string, string) {
	segments := strings.Split(msg, "\r")

	if len(segments) == 0 {
		return "", "", ""
	}

	mshFields := strings.Split(segments[0], "|")

	var (
		sendingApp      string
		sendingFacility string
	)

	if len(mshFields) > 3 {
		sendingApp = mshFields[2]
	}

	if len(mshFields) > 4 {
		sendingFacility = mshFields[3]
	}

	var ackCode string

	for _, seg := range segments[1:] {
		if strings.HasPrefix(seg, "MSA|") {
			fields := strings.Split(seg, "|")

			if len(fields) > 1 {
				ackCode = fields[1]
			}

			break
		}
	}

	return sendingApp, sendingFacility, ackCode
}

// hl7VendorHint maps well-known sending-application markers to cpemap keys.
func hl7VendorHint(sendingApp, sendingFacility string) string {
	lower := strings.ToLower(sendingApp + " " + sendingFacility)

	switch {
	case strings.Contains(lower, "mirth"):
		return "mirth_connect"
	case strings.Contains(lower, "epic"):
		return "epic_chronicles"
	case strings.Contains(lower, "cerner"):
		return "cerner_millennium"
	case strings.Contains(lower, "openmrs"):
		return "openmrs"
	case strings.Contains(lower, "openemr"):
		return "openemr"
	}

	return ""
}

// firstSegment trims a multi-segment HL7 message to its first segment,
// useful as a banner.
func firstSegment(msg string) string {
	if idx := strings.IndexByte(msg, '\r'); idx >= 0 {
		return msg[:idx]
	}

	if idx := strings.IndexByte(msg, '\n'); idx >= 0 {
		return msg[:idx]
	}

	return msg
}
