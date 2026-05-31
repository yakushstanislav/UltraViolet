package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const productISCSI = "iscsi_target"

func init() {
	// 3260 — IANA iSCSI default port.
	Register(probeISCSI, 3260)
}

// probeISCSI sends an iSCSI Login Request PDU with text key
// `InitiatorName=iqn.2024-01.uv.probe:scan` and discovery-session flags.
// The target's reply (Login Response PDU, opcode 0x23) carries either a
// success status with TargetName/TargetAddress text keys, or a rejection
// status whose mere presence already proves iSCSI is up.
//
// PDU layout (RFC 7143, §11.13):
//
//	BHS (48B): opcode 0x03 (Login Request) with T-bit set, …
//	          plus DataSegmentLength for the InitiatorName text key.
func probeISCSI(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	textData := buildISCSILoginText("uv-probe")

	bhs := make([]byte, 48)

	bhs[0] = 0x43
	bhs[1] = 0xC1
	bhs[2] = 0x00
	bhs[3] = 0x00

	binary.BigEndian.PutUint32(bhs[4:8], uint32(len(textData))&0x00FFFFFF)

	binary.BigEndian.PutUint64(bhs[8:16], 0)
	binary.BigEndian.PutUint64(bhs[16:24], 0)
	binary.BigEndian.PutUint32(bhs[24:28], 0)
	binary.BigEndian.PutUint16(bhs[28:30], 0)
	binary.BigEndian.PutUint16(bhs[30:32], 0)
	binary.BigEndian.PutUint32(bhs[32:36], 0)

	pad := (4 - len(textData)%4) % 4
	frame := make([]byte, 0, 48+len(textData)+pad)
	frame = append(frame, bhs...)
	frame = append(frame, textData...)

	if pad > 0 {
		frame = append(frame, make([]byte, pad)...)
	}

	if _, writeErr := conn.Write(frame); writeErr != nil {
		return nil, writeErr
	}

	respHeader := make([]byte, 48)

	if _, readErr := io.ReadFull(conn, respHeader); readErr != nil {
		return nil, errors.New("iscsi: short login reply")
	}

	opcode := respHeader[0] & 0x3F
	if opcode != 0x23 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	dsLen := int(binary.BigEndian.Uint32(append([]byte{0}, respHeader[5:8]...)))
	if dsLen < 0 || dsLen > 65535 {
		dsLen = 0
	}

	payload := make([]byte, dsLen)
	if dsLen > 0 {
		_, _ = io.ReadFull(conn, payload)
	}

	targetName, alias := parseISCSITextKeys(payload)

	fp := &FingerprintResult{
		Product: productISCSI,
		Edition: alias,
		RawJSON: mustMarshalJSON(map[string]any{
			"target_name": targetName,
			"alias":       alias,
		}),
	}

	banner := "iSCSI target"
	if targetName != "" {
		banner = "iSCSI target " + targetName
	}

	return &Result{
		Target:      target,
		Protocol:    productISCSI,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// buildISCSILoginText builds the text key segment for an iSCSI login
// discovery session.
func buildISCSILoginText(name string) []byte {
	text := "InitiatorName=iqn.2024-01.uv.probe:" + name + "\x00" +
		"SessionType=Discovery\x00" +
		"HeaderDigest=None\x00" +
		"DataDigest=None\x00"

	return []byte(text)
}

// parseISCSITextKeys walks a NULL-separated iSCSI key=value text segment
// looking for TargetName and TargetAlias.
func parseISCSITextKeys(data []byte) (string, string) {
	var (
		targetName  string
		targetAlias string
	)

	for _, kv := range strings.Split(string(data), "\x00") {
		switch {
		case strings.HasPrefix(kv, "TargetName="):
			targetName = strings.TrimPrefix(kv, "TargetName=")
		case strings.HasPrefix(kv, "TargetAlias="):
			targetAlias = strings.TrimPrefix(kv, "TargetAlias=")
		}
	}

	return targetName, targetAlias
}
