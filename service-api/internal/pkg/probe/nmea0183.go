package probe

import (
	"context"
	"strings"
	"time"
)

const productNMEA0183 = "nmea0183"

func init() {
	// 10110 — IANA-assigned NMEA 0183 over TCP.
	Register(probeNMEA0183, 10110)
}

// probeNMEA0183 connects to an NMEA 0183 TCP transponder and reads
// sentences for ~1.5s. Lines starting with the IEC 61162-style
// `$<talker><sentence>,...*XX` prefix confirm NMEA. We surface the
// talker IDs that showed up so cvematch can map e.g. AI* → AIS, GP* →
// GPS, SD* → depth sounder.
func probeNMEA0183(ctx context.Context, s *Stack, target Target) (*Result, error) {
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

	talkers, sentences := scanNMEASentences(raw)
	if len(sentences) == 0 {
		return &Result{Target: target, Protocol: protocolTCP, Banner: raw}, nil
	}

	product := productNMEA0183
	if containsAny(talkers, []string{"AI", "AB", "AD"}) {
		product = "ais_receiver"
	}

	fp := &FingerprintResult{
		Product: product,
		Edition: strings.Join(talkers, ","),
		RawJSON: mustMarshalJSON(map[string]any{
			"talkers":    talkers,
			"sentences":  sentences,
			"raw_sample": firstLine(raw),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    product,
		Banner:      strings.Join(sentences, " | "),
		Fingerprint: fp,
	}, nil
}

// scanNMEASentences extracts NMEA 0183 sentence types and talker IDs from
// a buffer of raw text. Returns the first 8 unique sentence prefixes and
// up to 4 talker IDs.
func scanNMEASentences(raw string) ([]string, []string) {
	var (
		talkers   []string
		sentences []string
	)

	seenTalkers := map[string]struct{}{}
	seenSentences := map[string]struct{}{}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")

		if len(line) < 7 || (line[0] != '$' && line[0] != '!') {
			continue
		}

		comma := strings.IndexByte(line, ',')
		if comma < 6 {
			continue
		}

		head := line[1:comma]

		if len(head) < 5 {
			continue
		}

		talker := head[:2]
		sentence := head[:5]

		if _, ok := seenTalkers[talker]; !ok && len(talkers) < 4 {
			talkers = append(talkers, talker)
			seenTalkers[talker] = struct{}{}
		}

		if _, ok := seenSentences[sentence]; !ok && len(sentences) < 8 {
			sentences = append(sentences, sentence)
			seenSentences[sentence] = struct{}{}
		}
	}

	return talkers, sentences
}

func containsAny(haystack, needles []string) bool {
	for _, h := range haystack {
		for _, n := range needles {
			if h == n {
				return true
			}
		}
	}

	return false
}
