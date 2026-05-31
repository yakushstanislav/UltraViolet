package probe

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"strings"
)

const productOCPP = "ocpp"

func init() {
	// 8887 is the de-facto default for self-hosted OCPP central
	// stations (Steve, MaEVe, Charge Point Manager, Wallbox myWallbox,
	// EV Manager, Compleo). 8889 is the plain-WS variant most often
	// seen in dev environments.
	Register(probeOCPP, 8887, 8889)
}

// probeOCPP detects an Open Charge Point Protocol central system. The
// protocol is plain WebSocket (with a fixed subprotocol name) running on
// top of either TLS (`wss://`, 8887) or bare TCP (`ws://`, 8889).
//
// Strategy:
//
//  1. Open the TCP socket. Wrap it in tls.Client to attempt a handshake;
//     if it succeeds we capture the leaf certificate for the TLS section
//     of the Result and reuse the encrypted connection for the WebSocket
//     upgrade. If the handshake fails we fall back to plain WebSocket on
//     the still-open TCP socket — most dev/staging chargers ship without
//     TLS.
//  2. Issue `GET /OCPP/CP_PROBE` with `Sec-WebSocket-Protocol: ocpp1.6,
//     ocpp2.0.1`. A central station compliant with OCPP-J either echoes
//     the subprotocol back in a 101 Switching Protocols, or replies with
//     a 4xx whose Server header / body still leaks the platform name.
//
// Even when the operator requires authentication, the presence of the
// negotiated `ocpp1.6` / `ocpp2.0.1` subprotocol header is enough to set
// Product=ocpp without sending any auth material.
func probeOCPP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	// Per-port heuristic: 8889 is plain WS, 8887/anything else tries TLS
	// first and falls back if the peer refuses to handshake.
	var (
		tlsResult *TLSResult
		transport = "ws"
		netConn   net.Conn
	)

	if target.Port == 8889 {
		netConn = conn
	} else {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // scanner probes self-signed CSMS certs
		if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
			return nil, errors.New("ocpp: TLS handshake failed and port is not the plain-WS one")
		}

		netConn = tlsConn
		transport = "wss"

		if leaf := firstPeerCert(tlsConn); leaf != nil {
			fingerprint := sha256.Sum256(leaf.Raw)
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

			tlsResult = &TLSResult{
				Subject:           leaf.Subject.String(),
				Issuer:            leaf.Issuer.String(),
				FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
				NotBefore:         leaf.NotBefore,
				NotAfter:          leaf.NotAfter,
				RawPEM:            string(pemBytes),
				SANs:              leaf.DNSNames,
			}
		}
	}

	return ocppUpgrade(target, netConn, tlsResult, transport)
}

// firstPeerCert pulls the leaf certificate out of a freshly-handshaked
// tls.Conn or returns nil when the peer presented none.
func firstPeerCert(c *tls.Conn) *x509.Certificate {
	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	return state.PeerCertificates[0]
}

// ocppUpgrade sends a single WebSocket upgrade request and inspects the
// reply for OCPP-specific markers.
func ocppUpgrade(target Target, conn net.Conn, tlsResult *TLSResult, transport string) (*Result, error) {
	host := net.JoinHostPort(target.IP.String(), "8887")

	key := base64.StdEncoding.EncodeToString([]byte("ultraviolet-ocpp-"))
	if len(key) > 24 {
		key = key[:24]
	}

	req := strings.Join([]string{
		"GET /OCPP/CP_PROBE HTTP/1.1",
		"Host: " + host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key: " + key,
		"Sec-WebSocket-Protocol: ocpp1.6, ocpp2.0.1",
		"User-Agent: UltraViolet/OCPP",
		"\r\n",
	}, "\r\n")

	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)

	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, errors.New("ocpp: malformed HTTP reply")
	}

	defer func() { _ = resp.Body.Close() }()

	bodyBuf := make([]byte, 1024)
	n, _ := resp.Body.Read(bodyBuf)
	body := strings.ToLower(string(bodyBuf[:n]))

	negotiated := resp.Header.Get("Sec-WebSocket-Protocol")
	server := resp.Header.Get("Server")

	confirmed := strings.Contains(strings.ToLower(negotiated), "ocpp") ||
		strings.Contains(body, "ocpp") ||
		ocppServerHint(server) != ""

	if !confirmed {
		fp := fingerprintFromHTTP(&HTTPResult{
			StatusCode: resp.StatusCode,
			Server:     server,
			Headers:    flattenHeaders(resp.Header),
		})

		return &Result{
			Target:      target,
			Protocol:    protocolHTTP,
			Banner:      server,
			TLS:         tlsResult,
			Fingerprint: fp,
		}, nil
	}

	product := productOCPP

	if hint := ocppServerHint(server); hint != "" {
		product = hint
	}

	fp := &FingerprintResult{
		Product: product,
		Edition: negotiated,
		RawJSON: mustMarshalJSON(map[string]any{
			"transport":           transport,
			"status_code":         resp.StatusCode,
			"negotiated_protocol": negotiated,
			"server_header":       server,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    product,
		Banner:      strings.TrimSpace(server + " " + negotiated),
		TLS:         tlsResult,
		Fingerprint: fp,
	}, nil
}

// ocppServerHint maps a vendor banner found in the Server header to a
// cpemap key. Empty result means "no specific vendor recognised".
func ocppServerHint(server string) string {
	if server == "" {
		return ""
	}

	lower := strings.ToLower(server)

	switch {
	case strings.Contains(lower, "steve"):
		return "steve_ocpp"
	case strings.Contains(lower, "maeve"):
		return "maeve_csms"
	case strings.Contains(lower, "wallbox"):
		return "wallbox_mywallbox"
	case strings.Contains(lower, "compleo"):
		return "compleo_csms"
	case strings.Contains(lower, "ev-manager"), strings.Contains(lower, "ev_manager"):
		return "ev_manager"
	}

	return ""
}

// flattenHeaders collapses an http.Header into a flat map[string]string,
// joining repeated values with ", " so callers can index by header name.
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))

	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}

	return out
}
