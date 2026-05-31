package probe

import (
	"context"
	"strings"
	"time"
)

const productDump1090 = "dump1090"

func init() {
	// 30003 — dump1090 BaseStation/SBS CSV output (read-only push).
	Register(probeDump1090, 30003)
}

// probeDump1090 reads BaseStation CSV records that dump1090 / readsb /
// piaware / fr24feed push on connect. A "MSG,1,..." through "MSG,8,..."
// line confirms the BaseStation feed.
func probeDump1090(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(1500 * time.Millisecond)

	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	_ = conn.SetReadDeadline(deadline)

	buf := make([]byte, 4096)

	n, _ := conn.Read(buf)
	if n == 0 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	raw := string(buf[:n])

	if !strings.Contains(raw, "MSG,") && !strings.Contains(raw, "AIR,") && !strings.Contains(raw, "SEL,") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: raw}, nil
	}

	msgTypes := scanADSBMsgTypes(raw)

	fp := &FingerprintResult{
		Product: productDump1090,
		RawJSON: mustMarshalJSON(map[string]any{
			"message_types": msgTypes,
			"raw_sample":    firstLine(raw),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productDump1090,
		Banner:      firstLine(raw),
		Fingerprint: fp,
	}, nil
}

// scanADSBMsgTypes returns the unique MSG,<N>,... transmission types seen
// in a BaseStation CSV chunk.
func scanADSBMsgTypes(raw string) []string {
	seen := map[string]struct{}{}

	var out []string

	for _, line := range strings.Split(raw, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ",", 3)
		if len(fields) < 2 || fields[0] != "MSG" {
			continue
		}

		if _, ok := seen[fields[1]]; ok {
			continue
		}

		seen[fields[1]] = struct{}{}
		out = append(out, fields[1])
	}

	return out
}
