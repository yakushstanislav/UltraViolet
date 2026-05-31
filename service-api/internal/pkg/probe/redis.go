package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
)

const productRedis = "redis"

func init() {
	Register(probeRedis, 6379)
}

// probeRedis sends PING + INFO server and derives version, mode, auth
// requirement from the RESP responses.
func probeRedis(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial Redis: %w", err)
	}

	defer func() { _ = conn.Close() }()

	pingResp, _ := redisRoundtrip(conn, "*1\r\n$4\r\nPING\r\n")
	infoResp, _ := redisRoundtrip(conn, "*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")

	version := redisInfoField(infoResp, "redis_version")
	mode := redisInfoField(infoResp, "redis_mode")
	osName := redisInfoField(infoResp, "os")

	authRequired := strings.HasPrefix(pingResp, "-NOAUTH") || strings.HasPrefix(pingResp, "NOAUTH")

	fp := &FingerprintResult{
		Product:      productRedis,
		Version:      version,
		AuthRequired: &authRequired,
		RawJSON: mustMarshalJSON(map[string]any{
			"ping_response": pingResp,
			"info_response": infoResp,
			"version":       version,
			"mode":          mode,
			"os":            osName,
		}),
	}

	if mode != "" {
		fp.ClusterRole = mode
	}

	if osName != "" {
		fp.Edition = osName
	}

	if infoResp != "" && !authRequired {
		fp.Anonymous = true
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Fingerprint: fp,
	}, nil
}

// redisRoundtrip writes a RESP command and returns the trimmed response.
func redisRoundtrip(conn net.Conn, cmd string) (string, error) {
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", err
	}

	buf := make([]byte, 8192)

	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}

	return strings.TrimRight(string(buf[:n]), "\r\n"), nil
}

// redisInfoField extracts a single "key:value" line from an INFO response.
func redisInfoField(info, key string) string {
	if info == "" {
		return ""
	}

	prefix := key + ":"

	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}

	return ""
}
