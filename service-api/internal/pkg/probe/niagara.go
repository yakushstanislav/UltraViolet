package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const productNiagaraFox = "tridium_niagara"

// foxHello is the Niagara Fox discovery payload used by nmap's fox-info.nse
// (typed fox.version / id fields). Plain "fox.version=1.0" still works on
// some controllers but misses others.
var foxHello = []byte("fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n")

var (
	niagaraFoxFieldRE  = regexp.MustCompile(`(?im)^\s*([\w.]+)\s*=\s*(?:[si]:\s*)?(.+?)\s*$`)
	niagaraFoxHeaderRE = regexp.MustCompile(`(?i)^fox\s+a\s+0\b`)
)

func init() {
	Register(probeNiagaraFox, 1911, 4911)
}

// probeNiagaraFox issues a Niagara Fox handshake compatible with nmap
// fox-info.nse: TLS-first (when offered), typed hello, fox a 0 validation,
// and parsing of the key=value block (app.version, brandId, hostId, …).
func probeNiagaraFox(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, usedTLS, err := s.dialFoxChannel(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	if _, writeErr := conn.Write(foxHello); writeErr != nil {
		return nil, fmt.Errorf("can't send Niagara Fox hello: %w", writeErr)
	}

	raw, err := readFoxResponse(conn, s.probeTimeout(ctx))
	if err != nil {
		return nil, fmt.Errorf("can't read Niagara Fox response: %w", err)
	}

	raw = strings.TrimRight(raw, "\x00\r\n; ")

	if raw == "" {
		return &Result{Target: target, Protocol: productNiagaraFox, Banner: "Niagara Fox"}, nil
	}

	if !isNiagaraFoxResponse(raw) {
		return &Result{Target: target, Protocol: protocolTCP, Banner: raw}, nil
	}

	fields := parseNiagaraFoxFields(raw)
	fp := fingerprintFromFoxFields(fields)

	fp.RawJSON = mustMarshalJSON(foxFieldsToMap(fields, usedTLS))

	banner := buildFoxBanner(fields, raw)

	return &Result{
		Target:      target,
		Protocol:    productNiagaraFox,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

func (s *Stack) dialFoxChannel(ctx context.Context, target Target) (net.Conn, bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	timeout := s.probeTimeout(ctx)

	tlsConn, err := (&tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // scanner probes arbitrary hosts
		},
	}).DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = tlsConn.SetDeadline(deadlineFromCtx(ctx, timeout))

		return tlsConn, true, nil
	}

	conn, dialErr := s.dialTCP(ctx, target)
	if dialErr != nil {
		return nil, false, dialErr
	}

	return conn, false, nil
}

func readFoxResponse(conn net.Conn, timeout time.Duration) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 8192)

	n, readErr := conn.Read(buf)
	if n == 0 && readErr != nil {
		return "", readErr
	}

	return string(buf[:n]), nil
}

func isNiagaraFoxResponse(raw string) bool {
	if niagaraFoxHeaderRE.MatchString(raw) {
		return true
	}

	lower := strings.ToLower(raw)

	return strings.Contains(lower, "fox.version") ||
		strings.Contains(lower, "app.version") ||
		strings.Contains(lower, "fox a")
}

type foxFields struct {
	FoxVersion  string
	HostName    string
	HostAddress string
	AppName     string
	AppVersion  string
	VMName      string
	VMVersion   string
	OSName      string
	TimeZone    string
	HostID      string
	ID          string
	VMUUID      string
	BrandID     string
	StationName string
	Fatal       string
}

func parseNiagaraFoxFields(raw string) foxFields {
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")

	body := raw
	if start >= 0 && end > start {
		body = raw[start+1 : end]
	}

	var out foxFields

	for _, line := range strings.Split(body, "\n") {
		match := niagaraFoxFieldRE.FindStringSubmatch(line)
		if len(match) < 3 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(match[1]))
		value := strings.TrimSpace(match[2])
		value = strings.TrimSuffix(value, ";")

		switch key {
		case "fox.version":
			out.FoxVersion = value
		case "hostname":
			out.HostName = value
		case "hostaddress":
			out.HostAddress = value
		case "app.name":
			out.AppName = value
		case "app.version":
			out.AppVersion = value
		case "vm.name":
			out.VMName = value
		case "vm.version":
			out.VMVersion = value
		case "os.name":
			out.OSName = value
		case "timezone":
			out.TimeZone = strings.Split(value, ";")[0]
		case "hostid":
			out.HostID = value
		case "id":
			out.ID = value
		case "vmuuid":
			out.VMUUID = value
		case "brandid":
			out.BrandID = value
		case "station.name":
			out.StationName = value
		case "fatal":
			out.Fatal = value
		}
	}

	return out
}

func fingerprintFromFoxFields(fields foxFields) *FingerprintResult {
	version := fields.AppVersion
	if version == "" {
		version = fields.FoxVersion
	}

	edition := fields.BrandID
	if edition == "" {
		edition = fields.HostID
	}

	if edition == "" {
		edition = fields.ID
	}

	if edition == "" && fields.AppName != "" {
		edition = fields.AppName
	}

	return &FingerprintResult{
		Product: productNiagaraFox,
		Version: version,
		Edition: edition,
	}
}

func foxFieldsToMap(fields foxFields, usedTLS bool) map[string]any {
	return map[string]any{
		"tls":          usedTLS,
		"fox.version":  fields.FoxVersion,
		"hostName":     fields.HostName,
		"hostAddress":  fields.HostAddress,
		"app.name":     fields.AppName,
		"app.version":  fields.AppVersion,
		"vm.name":      fields.VMName,
		"vm.version":   fields.VMVersion,
		"os.name":      fields.OSName,
		"timeZone":     fields.TimeZone,
		"hostId":       fields.HostID,
		"id":           fields.ID,
		"vmUuid":       fields.VMUUID,
		"brandId":      fields.BrandID,
		"station.name": fields.StationName,
		"fatal":        fields.Fatal,
	}
}

func buildFoxBanner(fields foxFields, raw string) string {
	if fields.AppName != "" && fields.AppVersion != "" {
		return "Niagara Fox " + fields.AppName + " " + fields.AppVersion
	}

	if fields.HostName != "" {
		return "Niagara Fox " + fields.HostName
	}

	if len(raw) > 512 {
		return raw[:512]
	}

	return raw
}
