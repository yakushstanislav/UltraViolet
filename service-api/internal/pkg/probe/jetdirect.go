package probe

import (
	"context"
	"fmt"
	"strings"
)

const productJetdirect = "jetdirect"

func init() {
	Register(probeJetdirect, 9100)
}

// probeJetdirect uses PJL (Printer Job Language) over the well-known raw
// print port 9100 to ask the printer for its model and firmware revision.
// PJL is supported by every HP LaserJet, every Brother NC-series, most
// Kyocera/Lexmark/Xerox/Ricoh machines and by Zebra/SATO label printers.
//
// The probe is single-shot: we send a UEL (Universal Exit Language) wrap
// containing @PJL INFO ID and @PJL INFO STATUS, then read whatever the
// printer wants to dribble back before the connection idles out. PJL is
// human-readable so we don't need a binary parser.
//
// CVE relevance: PJL printers are a well-known foothold (CVE-2017-2741,
// CVE-2022-2080, the "Pwn2Own Mobile" stream of HP iLO bugs) and the model
// string maps directly onto product entries in cpemap.productMap when one
// exists; otherwise we ship plain "jetdirect" so cvematch can still hit
// generic LPD/PJL CVEs.
func probeJetdirect(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial JetDirect: %w", err)
	}

	defer func() { _ = conn.Close() }()

	const pjlExit = "\x1B%-12345X"

	req := pjlExit +
		"@PJL INFO ID\r\n" +
		"@PJL INFO STATUS\r\n" +
		"@PJL INFO PRODINFO\r\n" +
		pjlExit

	if _, writeErr := conn.Write([]byte(req)); writeErr != nil {
		return nil, fmt.Errorf("can't write PJL INFO: %w", writeErr)
	}

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		// Some printers go silent until they get a print job. Mark them
		// as a printer anyway so cvematch picks up port-9100 CVEs.
		return &Result{Target: target, Protocol: productJetdirect}, nil
	}

	raw := strings.TrimRight(string(buf[:n]), "\x00 \r\n\f")

	model := extractPJLField(raw, "ID")
	revision := extractPJLField(raw, "FORMATTER")

	if model == "" {
		// Look for product line in PRODINFO block:
		//   @PJL INFO PRODINFO\r\n
		//   PROD INFO PRODUCT="HP LaserJet 600 M601"
		model = extractPJLProductLine(raw)
	}

	product := productJetdirect

	switch {
	case containsFold(model, "laserjet"), containsFold(model, "officejet"), containsFold(model, "deskjet"):
		product = "hp_printer"
	case containsFold(model, "brother"):
		product = "brother_printer"
	case containsFold(model, "kyocera"):
		product = "kyocera_printer"
	case containsFold(model, "lexmark"):
		product = "lexmark_printer"
	case containsFold(model, "xerox"):
		product = "xerox_printer"
	case containsFold(model, "ricoh"):
		product = "ricoh_printer"
	case containsFold(model, "epson"):
		product = "epson_printer"
	case containsFold(model, "canon"):
		product = "canon_printer"
	}

	fp := &FingerprintResult{
		Product: product,
		Version: revision,
		Edition: model,
		RawJSON: mustMarshalJSON(map[string]any{
			"model":    model,
			"revision": revision,
			"raw":      raw,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productJetdirect,
		Banner:      strings.TrimSpace(model + " " + revision),
		Fingerprint: fp,
	}, nil
}

// extractPJLField pulls a single quoted/unquoted field out of a PJL reply.
// Replies look like:
//
//	@PJL INFO ID
//	"hp LaserJet 600 M601"
//	\f
//
// or
//
//	@PJL INFO FORMATTER
//	FORMATTER REVISION = 20190108
//	\f
func extractPJLField(raw, name string) string {
	upper := strings.ToUpper(raw)
	idx := strings.Index(upper, "@PJL INFO "+name)

	if idx < 0 {
		return ""
	}

	rest := raw[idx:]

	// Skip the "@PJL INFO NAME" line.
	if newline := strings.Index(rest, "\n"); newline >= 0 {
		rest = rest[newline+1:]
	}

	if formFeed := strings.IndexByte(rest, '\f'); formFeed >= 0 {
		rest = rest[:formFeed]
	}

	if nextHeader := strings.Index(rest, "@PJL"); nextHeader >= 0 {
		rest = rest[:nextHeader]
	}

	value := strings.TrimSpace(rest)
	value = strings.Trim(value, "\"")

	if idx := strings.Index(value, "="); idx >= 0 {
		value = strings.TrimSpace(value[idx+1:])
	}

	value = strings.Split(value, "\r")[0]
	value = strings.Split(value, "\n")[0]
	value = strings.Trim(value, "\" ")

	return value
}

// extractPJLProductLine pulls the PRODUCT="..." token out of a PRODINFO
// block when present, for printers that don't honour @PJL INFO ID.
func extractPJLProductLine(raw string) string {
	upper := strings.ToUpper(raw)

	idx := strings.Index(upper, "PRODUCT=")
	if idx < 0 {
		return ""
	}

	value := raw[idx+len("PRODUCT="):]
	value = strings.TrimSpace(value)

	if strings.HasPrefix(value, "\"") {
		value = strings.TrimPrefix(value, "\"")

		if end := strings.IndexByte(value, '"'); end >= 0 {
			return value[:end]
		}
	}

	value = strings.Split(value, "\r")[0]
	value = strings.Split(value, "\n")[0]

	return strings.TrimSpace(value)
}
