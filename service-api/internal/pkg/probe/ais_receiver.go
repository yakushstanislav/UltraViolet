package probe

import (
	"context"
	"strings"
	"time"
)

const productAISReceiver = "ais_receiver"

func init() {
	// 5631 — pcAnywhere control TCP was originally assigned here, but
	// modern OpenCPN / aishub.net / AisDispatcher deployments default
	// to 5631 for AIS NMEA-over-TCP. No collision with any existing
	// registered port.
	Register(probeAISReceiver, 5631)
}

// probeAISReceiver reads NMEA 0183 sentences for ~1.5s. Lines beginning
// with `!AIVDM`, `!AIVDO`, `$AIVDM` or `$ANVDM` are the canonical AIS
// payloads (talker IDs AI / AN / AB / AD).
func probeAISReceiver(ctx context.Context, s *Stack, target Target) (*Result, error) {
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

	if !strings.Contains(raw, "!AIVDM") &&
		!strings.Contains(raw, "!AIVDO") &&
		!strings.Contains(raw, "$AIVDM") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: raw}, nil
	}

	_, sentences := scanNMEASentences(raw)

	fp := &FingerprintResult{
		Product: productAISReceiver,
		RawJSON: mustMarshalJSON(map[string]any{
			"sentences":  sentences,
			"raw_sample": firstLine(raw),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productAISReceiver,
		Banner:      firstLine(raw),
		Fingerprint: fp,
	}, nil
}
