// Tesla Wall Connector Gen 3 fingerprinter. The device exposes a public,
// unauthenticated read-only JSON API on port 80 (legacy firmware) and
// port 443 (current firmware, self-signed cert with Subject
// "Tesla Wall Connector Gen 3"):
//
//   GET /api/1/vitals  → contactor_closed, vehicle_connected, session_s,
//                        grid_v, grid_hz, firmware_version, mcu_temp_c,
//                        evse_state, …
//   GET /api/1/version → firmware_version, part_number, serial_number
//
// The standard probeHTTP / probeHTTPS already captures the response body
// for the scanner — there's no need for a dedicated TCP probe on top.
// What's missing is a body-shape parser that recognises the JSON pair
// `"evse_state"` + `"firmware_version"` as uniquely Tesla. This file
// adds that parser and wires it into fingerprintFromHTTP via a final
// body-shape check after the canonical Server / X-Powered-By /
// X-Generator / <meta generator> chain.
//
// The TLS Subject side of detection is handled in derived.go's
// tlsSubjectHints ("tesla wall connector" / "tesla, inc").

package probe

import (
	"regexp"
	"strings"
)

// teslaFirmwareRE pulls `"firmware_version": "<value>"` out of the JSON
// payload. The version field on Tesla Wall Connector Gen 3 is shaped
// like "24.36.5+gxxxxxx" — semver-ish prefix plus a git-hash suffix.
// We capture the full string and let cpemap.normalizeVersion strip the
// "+gxxxxxx" build tag at comparison time.
var teslaFirmwareRE = regexp.MustCompile(`"firmware_version"\s*:\s*"([^"]+)"`)

// detectTeslaWallConnector inspects an HTTP response body for the
// JSON-shape fingerprint that only Tesla Wall Connector Gen 3 firmware
// emits: a flat object that pairs an `evse_state` enum with a
// `firmware_version` string (on /api/1/vitals; /api/1/version drops
// `evse_state` but adds `part_number` and `serial_number`).
//
// Returns nil when the body doesn't look like a Tesla Wall Connector
// response, so callers can keep the existing fingerprint in that case.
func detectTeslaWallConnector(httpResult *HTTPResult) *FingerprintResult {
	if httpResult == nil || httpResult.Body == "" {
		return nil
	}

	body := httpResult.Body

	hasFirmware := strings.Contains(body, `"firmware_version"`)
	if !hasFirmware {
		return nil
	}

	// /api/1/vitals signature.
	hasEVSE := strings.Contains(body, `"evse_state"`)

	// /api/1/version signature (Tesla-unique serial prefix "PG").
	hasPart := strings.Contains(body, `"part_number"`) && strings.Contains(body, `"serial_number"`)

	if !hasEVSE && !hasPart {
		return nil
	}

	fp := &FingerprintResult{Product: "tesla_wall_connector"}

	if match := teslaFirmwareRE.FindStringSubmatch(body); len(match) == 2 {
		fp.Version = strings.TrimSpace(match[1])
	}

	return fp
}
