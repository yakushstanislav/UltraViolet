package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
)

const productPostgres = "postgresql"

func init() {
	Register(probePostgres, 5432)
}

// probePostgres performs the PostgreSQL startup handshake to extract server
// parameters (version), capture an SSL upgrade if offered, and report
// whether authentication is required.
func probePostgres(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial PostgreSQL: %w", err)
	}

	defer func() { _ = conn.Close() }()

	var tlsRes *TLSResult

	isSSL := false

	if upgraded, leaf, ok := tryPostgresTLSUpgrade(ctx, conn, target.IP.String()); ok {
		conn = upgraded
		isSSL = true

		if leaf != nil {
			tlsRes = leafCertToResult(leaf)
		}
	}

	startup := buildPostgresStartupMessage("scanner", "postgres")
	if _, err = conn.Write(startup); err != nil {
		return nil, fmt.Errorf("can't write PostgreSQL startup message: %w", err)
	}

	serverParams, authRequired := readPostgresStartupResponse(conn)

	fp := &FingerprintResult{
		Product:      productPostgres,
		Version:      serverParams["server_version"],
		AuthRequired: &authRequired,
		TLSRequired:  &isSSL,
		RawJSON: mustMarshalJSON(map[string]any{
			"is_ssl":             isSSL,
			"server_parameters":  serverParams,
			"supported_versions": "3.0",
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		Fingerprint: fp,
		TLS:         tlsRes,
	}, nil
}

// tryPostgresTLSUpgrade sends the SSLRequest startup message and, if the
// server replies with 'S', completes a TLS handshake on the same socket.
// Returns the upgraded connection, the leaf certificate, and ok=true only
// when the upgrade fully succeeded.
func tryPostgresTLSUpgrade(ctx context.Context, conn net.Conn, serverName string) (net.Conn, *x509.Certificate, bool) {
	if _, err := conn.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
		return conn, nil, false
	}

	reply := make([]byte, 1)
	if _, err := conn.Read(reply); err != nil || reply[0] != 'S' {
		return conn, nil, false
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // scanner probes arbitrary hosts
		ServerName:         serverName,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return conn, nil, false
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tlsConn, nil, true
	}

	return tlsConn, state.PeerCertificates[0], true
}

// readPostgresStartupResponse drains backend messages until ReadyForQuery
// or EOF and returns server parameters plus whether authentication is
// expected from the client.
func readPostgresStartupResponse(conn net.Conn) (map[string]string, bool) {
	serverParams := map[string]string{}
	authRequired := false

	for range 8 {
		msgType := make([]byte, 1)
		if _, err := conn.Read(msgType); err != nil {
			return serverParams, authRequired
		}

		lenBuf := make([]byte, 4)
		if _, err := conn.Read(lenBuf); err != nil {
			return serverParams, authRequired
		}

		msgLen := int(binary.BigEndian.Uint32(lenBuf))
		if msgLen < 4 || msgLen > 64*1024 {
			return serverParams, authRequired
		}

		payload := make([]byte, msgLen-4)
		if _, err := conn.Read(payload); err != nil {
			return serverParams, authRequired
		}

		switch msgType[0] {
		case 'R':
			if len(payload) >= 4 {
				authCode := int(binary.BigEndian.Uint32(payload[:4]))
				authRequired = authCode != 0
			}
		case 'S':
			if key, val := parsePostgresCStringPair(payload); key != "" {
				serverParams[key] = val
			}
		case 'E':
			authRequired = true
		case 'Z':
			return serverParams, authRequired
		}
	}

	return serverParams, authRequired
}

func buildPostgresStartupMessage(user, db string) []byte {
	payload := bytes.NewBuffer(nil)
	_, _ = payload.Write([]byte{0, 3, 0, 0})
	_, _ = payload.WriteString("user")
	_ = payload.WriteByte(0)
	_, _ = payload.WriteString(user)
	_ = payload.WriteByte(0)
	_, _ = payload.WriteString("database")
	_ = payload.WriteByte(0)
	_, _ = payload.WriteString(db)
	_ = payload.WriteByte(0)
	_ = payload.WriteByte(0)

	totalLen := int32(payload.Len() + 4)
	out := bytes.NewBuffer(nil)
	_ = binary.Write(out, binary.BigEndian, totalLen)
	_, _ = out.Write(payload.Bytes())

	return out.Bytes()
}

func parsePostgresCStringPair(in []byte) (string, string) {
	parts := bytes.Split(in, []byte{0})
	if len(parts) < 2 {
		return "", ""
	}

	return string(parts[0]), string(parts[1])
}
