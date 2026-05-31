package probe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const productZookeeper = "zookeeper"

// zookeeperVersionRE matches the first line of the `stat`/`srvr` 4lw response:
//
//	Zookeeper version: 3.8.3-6ad6d364c7c0bcf0de452d54ebefa3058098ab56, ...
var zookeeperVersionRE = regexp.MustCompile(`(?im)^Zookeeper version:\s*([^\s,]+)`)

func init() {
	Register(probeZookeeper, 2181)
}

// probeZookeeper sends the `srvr` 4-letter word (a superset of `stat` that
// doesn't dump session lists) and parses the resulting banner.
//
// Note: as of ZooKeeper 3.5 the 4lw commands are gated by the
// `4lw.commands.whitelist` config. Hardened clusters refuse and close the
// connection — in that case we fall back to a plain banner without a
// FingerprintResult, which is the same outcome as the generic banner probe.
func probeZookeeper(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial ZooKeeper: %w", err)
	}

	defer func() { _ = conn.Close() }()

	if _, writeErr := conn.Write([]byte("srvr")); writeErr != nil {
		return nil, fmt.Errorf("can't send srvr 4lw: %w", writeErr)
	}

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	raw := strings.TrimRight(string(buf[:n]), "\r\n\x00")

	match := zookeeperVersionRE.FindStringSubmatch(raw)
	if len(match) < 2 {
		// 4lw disabled or response truncated — keep the banner around so the
		// operator can still see what came back.
		return &Result{Target: target, Protocol: productZookeeper, Banner: raw}, nil
	}

	version := match[1]
	if idx := strings.Index(version, "-"); idx > 0 {
		version = version[:idx]
	}

	fp := &FingerprintResult{
		Product: productZookeeper,
		Version: version,
		RawJSON: mustMarshalJSON(map[string]any{
			"srvr_response": raw,
			"version":       version,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Banner:      raw,
		Fingerprint: fp,
	}, nil
}
