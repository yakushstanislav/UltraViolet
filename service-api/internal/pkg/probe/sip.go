package probe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const productSIP = "sip_server"

func init() {
	// SIP — VoIP PBXes (Asterisk / FreePBX / 3CX / FreeSWITCH /
	// Kamailio / OpenSIPS) and IP phones (Cisco, Polycom, Yealink,
	// Grandstream, Mitel) usually respond to a stateless OPTIONS on
	// UDP 5060; TCP 5060 for the same OPTIONS probe.
	RegisterUDP(probeSIP, 5060)
	Register(probeSIP, 5060)
}

// probeSIP issues a stateless SIP OPTIONS request and parses the response
// for the Server / User-Agent header — they are the de facto vendor
// fingerprint on UDP 5060.
func probeSIP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	var (
		conn net.Conn
		err  error
	)

	if target.Transport == TransportUDP {
		conn, err = s.dialUDP(ctx, target)
	} else {
		conn, err = s.dialTCP(ctx, target)
	}

	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	request := buildSIPOptionsRequest(target)

	if _, writeErr := conn.Write([]byte(request)); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)
	if err != nil || n < 16 {
		return nil, errors.New("sip: no SIP reply")
	}

	body := buf[:n]
	if !bytes.HasPrefix(body, []byte("SIP/2.0")) {
		return &Result{Target: target, Protocol: productSIP}, nil
	}

	statusLine, headers := parseSIPResponse(body)

	server := headers["server"]
	userAgent := headers["user-agent"]

	banner := server
	if banner == "" {
		banner = userAgent
	}

	if banner == "" {
		banner = statusLine
	}

	fp := &FingerprintResult{
		Product: productSIP,
		RawJSON: mustMarshalJSON(map[string]any{
			"status":     statusLine,
			"server":     server,
			"user_agent": userAgent,
			"allow":      headers["allow"],
			"supported":  headers["supported"],
		}),
	}

	if product, version := classifySIPBanner(server + " " + userAgent); product != "" {
		fp.Product = product
		fp.Version = version
	}

	return &Result{
		Target:      target,
		Protocol:    productSIP,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

func buildSIPOptionsRequest(target Target) string {
	host := target.IP.String()

	transport := "TCP"
	if target.Transport == TransportUDP {
		transport = "UDP"
	}

	return strings.Join([]string{
		fmt.Sprintf("OPTIONS sip:nobody@%s:%d SIP/2.0", host, target.Port),
		fmt.Sprintf("Via: SIP/2.0/%s %s:%d;branch=z9hG4bK-ultraviolet", transport, host, target.Port),
		"Max-Forwards: 70",
		fmt.Sprintf("To: <sip:nobody@%s>", host),
		"From: <sip:probe@ultraviolet>;tag=ultraviolet-probe",
		"Call-ID: ultraviolet-probe@ultraviolet",
		"CSeq: 1 OPTIONS",
		"Contact: <sip:probe@127.0.0.1>",
		"Accept: application/sdp",
		"User-Agent: UltraViolet/1.0",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
}

// parseSIPResponse splits a raw SIP reply into the status line and a
// case-insensitive header map. Headers that may repeat (Via, Allow,
// Supported) are concatenated with comma+space; that loses nothing for
// our fingerprinting purposes.
func parseSIPResponse(body []byte) (string, map[string]string) {
	out := map[string]string{}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 8192), 8192)

	statusLine := ""

	if scanner.Scan() {
		statusLine = strings.TrimRight(scanner.Text(), "\r\n")
	}

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" {
			break
		}

		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])

		if existing, ok := out[key]; ok && existing != "" {
			out[key] = existing + ", " + val

			continue
		}

		out[key] = val
	}

	return statusLine, out
}

// sipBannerPattern maps a regexp on the concatenated Server/User-Agent
// string to a cpemap product key. The optional version capture group
// becomes FingerprintResult.Version.
type sipBannerPattern struct {
	re      *regexp.Regexp
	product string
}

var sipBannerPatterns = []sipBannerPattern{
	{regexp.MustCompile(`(?i)Asterisk\s*(?:PBX)?\s*v?([\w.\-]+)?`), "asterisk_pbx"},
	{regexp.MustCompile(`(?i)FreePBX\s*v?([\w.\-]+)?`), "freepbx"},
	{regexp.MustCompile(`(?i)3CX\s+(?:Phone\s+System)?\s*v?([\w.\-]+)?`), "tcx_phone_system"},
	{regexp.MustCompile(`(?i)FreeSWITCH-mod_sofia/([\w.\-]+)?`), "freeswitch"},
	{regexp.MustCompile(`(?i)FreeSWITCH\s*v?([\w.\-]+)?`), "freeswitch"},
	{regexp.MustCompile(`(?i)Kamailio\s*\(?([\w.\-]+)?`), "kamailio"},
	{regexp.MustCompile(`(?i)OpenSIPS\s*\(?([\w.\-]+)?`), "opensips"},
	{regexp.MustCompile(`(?i)Mitel\s+SIP[^\n]*?v?([\w.\-]+)?`), "mitel_sip"},
	{regexp.MustCompile(`(?i)Cisco-SIPGateway/IOS-([\w.\-]+)?`), "cisco_sip_gateway"},
	{regexp.MustCompile(`(?i)Cisco\s+(?:CUCM|Unified)[^\n]*?v?([\w.\-]+)?`), "cisco_cucm"},
	{regexp.MustCompile(`(?i)Yealink\s+SIP-([\w.\-]+)?`), "yealink_phone"},
	{regexp.MustCompile(`(?i)Polycom\s+([\w.\-]+)?`), "polycom_phone"},
	{regexp.MustCompile(`(?i)Grandstream\s+([\w.\-]+)?`), "grandstream_phone"},
	{regexp.MustCompile(`(?i)Avaya\s+(?:CM|SBCE|Aura)[^\n]*?v?([\w.\-]+)?`), "avaya_aura"},
	{regexp.MustCompile(`(?i)Sangoma\s+([\w.\-]+)?`), "sangoma_pbx"},
}

func classifySIPBanner(s string) (string, string) {
	for _, p := range sipBannerPatterns {
		match := p.re.FindStringSubmatch(s)
		if match == nil {
			continue
		}

		version := ""

		if len(match) > 1 {
			version = strings.TrimSpace(match[1])
		}

		return p.product, version
	}

	return "", ""
}
