package probe

import (
	"context"
	"fmt"
	"strings"
)

const maxBannerBytes = 1024

// probeBanner is the fallback used for unknown ports.
//
// Step 1: read up to maxBannerBytes — many servers (FTP/SSH/SMTP/etc.) push a
// greeting immediately on connect, which is enough to fingerprint them.
//
// Step 2: if those bytes already look like a TLS handshake record, defer to
// probeHTTPS — it can complete the TLS exchange and capture the cert chain.
//
// Step 3: when the server stays silent (n == 0, typical for HTTPS-only and
// many app servers on non-standard ports — k8s-apiserver:6443, vault:8200,
// kubelet:10250, etcd:2379 with TLS, …) try a client-initiated TLS
// handshake. If that succeeds we hand off to probeHTTPS to pull the cert
// plus a best-effort HTTPS GET. This turns the "unknown TCP" black-box on
// random ports into a real fingerprint for any TLS-fronted service.
func (s *Stack) probeBanner(ctx context.Context, target Target) (*Result, error) {
	conn, err := s.dialTCPWithTimeout(ctx, target, s.bannerTimeout(ctx))
	if err != nil {
		return nil, fmt.Errorf("can't dial for banner: %w", err)
	}

	defer func() { _ = conn.Close() }()

	buf := make([]byte, maxBannerBytes)

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		_ = conn.Close()

		if tlsResult, tlsErr := s.handshakeTLS(ctx, target); tlsErr == nil && tlsResult != nil {
			return s.probeHTTPSWithTLS(ctx, target, tlsResult), nil
		}

		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	raw := buf[:n]

	if looksLikeTLSHandshakeRecord(raw) {
		return probeHTTPS(ctx, s, target)
	}

	banner := strings.TrimRight(string(raw), "\r\n\x00")

	return &Result{
		Target:     target,
		Protocol:   detectProtocol(target.Port, banner),
		Banner:     banner,
		Components: ExtractFromText(banner),
	}, nil
}

// looksLikeTLSHandshakeRecord reports whether the prefix looks like a TLS
// handshake record (content type 22, version 0x03xx) as sent by many TLS
// servers immediately after accept.
func looksLikeTLSHandshakeRecord(prefix []byte) bool {
	if len(prefix) < 5 {
		return false
	}

	if prefix[0] != 0x16 {
		return false
	}

	if prefix[1] != 0x03 {
		return false
	}

	return prefix[2] <= 0x04
}

// detectProtocol guesses the protocol label from the port number with a
// banner-prefix fallback. Conservative: returns protocolTCP when unsure.
func detectProtocol(port uint16, banner string) string {
	switch port {
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 25, 465, 587:
		return "smtp"
	}

	switch {
	case strings.HasPrefix(banner, "SSH-"):
		return "ssh"
	case strings.HasPrefix(banner, "220 ") && strings.Contains(strings.ToLower(banner), "ftp"):
		return "ftp"
	case strings.HasPrefix(banner, "220 ") && strings.Contains(strings.ToLower(banner), "smtp"):
		return "smtp"
	case strings.HasPrefix(banner, "RTSP/"):
		return productRTSP
	case strings.HasPrefix(banner, "SIP/2.0"):
		return productSIP
	case strings.HasPrefix(banner, "RFB "):
		return "vnc"
	case strings.Contains(banner, "USERID"):
		return productIdent
	case strings.Contains(strings.ToLower(banner), "method: rsync"):
		return productRsync
	case strings.HasPrefix(banner, "BitTorrent protocol"):
		return productBitTorrent
	case strings.Contains(banner, "NetBIOS session"):
		return productNetBIOS
	case strings.Contains(strings.ToUpper(banner), "IMPLEMENTATION"):
		return productManageSieve
	}

	return protocolTCP
}
