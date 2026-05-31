package probe

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

const productVxWorks = "wind_river_vxworks"

func init() {
	// 17185 — VxWorks WDB Agent. Canonically UDP per Wind River docs, but
	// some images expose the same agent over TCP (carrier-grade switches,
	// older Tornado-shipped firmware). Scanning by IP literal still finds
	// these TCP listeners — we banner-sniff and only fingerprint when the
	// payload mentions VxWorks/WindRiver/RTP/Tornado.
	Register(probeVxWorksWDB, 17185)
}

func probeVxWorksWDB(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial VxWorks WDB target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	// Some agents send a banner on accept. The ones that don't will close
	// the connection after the deadline expires — that's not a positive
	// for VxWorks, so we fall through to a generic banner result.
	buf := make([]byte, 1024)

	n, _ := io.ReadFull(conn, buf)
	if n == 0 {
		extra, _ := conn.Read(buf)
		n = extra
	}

	if n == 0 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	reply := strings.TrimRight(string(buf[:n]), "\x00\r\n ")
	low := strings.ToLower(reply)

	if !strings.Contains(low, "vxworks") &&
		!strings.Contains(low, "wdb") &&
		!strings.Contains(low, "windriver") &&
		!strings.Contains(low, "wind river") &&
		!strings.Contains(low, "tornado") {
		return &Result{Target: target, Protocol: protocolTCP, Banner: reply}, nil
	}

	return &Result{
		Target:   target,
		Protocol: productVxWorks,
		Banner:   reply,
		Fingerprint: &FingerprintResult{
			Product: productVxWorks,
			RawJSON: mustMarshalJSON(map[string]any{
				"reply":      reply,
				"transport":  "tcp",
				"wdb_marker": true,
			}),
		},
	}, nil
}
