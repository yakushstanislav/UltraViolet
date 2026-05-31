package handler

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// onvifLenientHeaderMax bounds the raw response header block we are willing to
// buffer and sanitize.
const onvifLenientHeaderMax = 32 * 1024

// onvifLenientDialTimeout caps the TCP/TLS connect step. Cameras tend to be
// slow to accept but a hard ceiling avoids hangs when the device is offline.
const onvifLenientDialTimeout = 10 * time.Second

// onvifLenientTransport is a minimal HTTP/1.1 RoundTripper used for ONVIF SOAP
// traffic. It exists for one reason: cheap IP cameras commonly emit malformed
// response headers (e.g. a bare "Www-Authenticate" line without ':' before the
// Digest challenge), which the standard net/http transport rejects with
// "malformed MIME header: missing colon". This transport opens a fresh
// TCP/TLS connection, writes the request, reads the response header block
// itself, rewrites lines that don't parse, and only then hands the byte
// stream to http.ReadResponse so the rest of net/http (and the digest
// transport on top) keeps working unchanged.
//
// Keep-alive is intentionally disabled. ONVIF calls are infrequent and the
// extra socket per request keeps the lenient path simple and predictable.
type onvifLenientTransport struct {
	TLSConfig   *tls.Config
	DialTimeout time.Duration
}

func newONVIFLenientTransport() *onvifLenientTransport {
	return &onvifLenientTransport{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // passive-probe policy: cameras use self-signed TLS
			NextProtos:         []string{"http/1.1"},
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
			MinVersion:         tls.VersionTLS12,
		},
		DialTimeout: onvifLenientDialTimeout,
	}
}

// RoundTrip implements http.RoundTripper.
func (t *onvifLenientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		if req.URL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	ctx := req.Context()

	dialer := &net.Dialer{Timeout: t.DialTimeout}

	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}

	if req.URL.Scheme == "https" {
		tlsCfg := t.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // passive-probe policy
		}

		tlsCfg = tlsCfg.Clone()

		if tlsCfg.ServerName == "" {
			h, _, splitErr := net.SplitHostPort(host)
			if splitErr == nil {
				tlsCfg.ServerName = h
			}
		}

		tlsConn := tls.Client(conn, tlsCfg)
		if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
			_ = conn.Close()

			return nil, hsErr
		}

		conn = tlsConn
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	reqCopy := req.Clone(ctx)
	reqCopy.Close = true

	if err = reqCopy.Write(conn); err != nil {
		_ = conn.Close()

		return nil, err
	}

	br := bufio.NewReader(conn)

	var headerBuf bytes.Buffer

	for headerBuf.Len() < onvifLenientHeaderMax {
		line, readErr := br.ReadBytes('\n')
		if len(line) > 0 {
			headerBuf.Write(line)
		}

		if readErr != nil {
			_ = conn.Close()

			return nil, readErr
		}

		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
	}

	if headerBuf.Len() >= onvifLenientHeaderMax {
		_ = conn.Close()

		return nil, errors.New("onvif lenient transport: header block too large")
	}

	sanitized := sanitizeONVIFHeaders(headerBuf.Bytes())

	combined := io.MultiReader(bytes.NewReader(sanitized), br)

	resp, err := http.ReadResponse(bufio.NewReader(combined), reqCopy)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	resp.Body = &onvifConnClosingBody{ReadCloser: resp.Body, conn: conn}

	return resp, nil
}

// sanitizeONVIFHeaders rewrites the raw header block of a single HTTP/1.x
// response so http.ReadResponse can parse it. The status line (line 0) is
// preserved as-is. For every subsequent header line:
//
//   - lines with a ':' are kept verbatim;
//   - leading-whitespace lines without ':' are treated as RFC 7230 obs-fold
//     and appended to the previous header value;
//   - everything else (non-empty lines without ':') is dropped.
//
// The empty terminating line (\r\n) is preserved.
func sanitizeONVIFHeaders(raw []byte) []byte {
	lines := bytes.Split(raw, []byte("\r\n"))
	out := make([][]byte, 0, len(lines))

	for i, line := range lines {
		if i == 0 {
			out = append(out, line)

			continue
		}

		if len(line) == 0 {
			out = append(out, line)

			continue
		}

		if bytes.IndexByte(line, ':') != -1 {
			out = append(out, line)

			continue
		}

		if (line[0] == ' ' || line[0] == '\t') && len(out) > 0 {
			folded := append(out[len(out)-1], ' ')
			folded = append(folded, bytes.TrimLeft(line, " \t")...)
			out[len(out)-1] = folded

			continue
		}
	}

	return bytes.Join(out, []byte("\r\n"))
}

// onvifConnClosingBody ties resp.Body lifetime to the underlying connection so
// closing the body releases the socket (we don't keep-alive ONVIF sessions).
type onvifConnClosingBody struct {
	io.ReadCloser
	conn   net.Conn
	closed bool
}

func (b *onvifConnClosingBody) Close() error {
	if b.closed {
		return nil
	}

	b.closed = true

	bodyErr := b.ReadCloser.Close()

	if connErr := b.conn.Close(); bodyErr == nil {
		bodyErr = connErr
	}

	return bodyErr
}
