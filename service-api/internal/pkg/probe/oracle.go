package probe

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const productOracleTNS = "oracle_database"

func init() {
	// Oracle Net "Listener" (TNS) — TCP 1521 is the canonical port; 1522
	// is the common second listener; 1525/2483 are documented IANA
	// assignments still seen on RAC clusters and Times Ten instances.
	Register(probeOracleTNS, 1521, 1522, 1525, 2483)
}

// probeOracleTNS performs an Oracle Net "Listener" TNS CONNECT handshake
// and classifies the response.
//
// The CONNECT carries a textual DESCRIPTOR (the same kind sqlplus puts in
// tnsnames.ora) wrapped in an 8-byte TNS header and a 42-byte CONNECT
// body. The listener answers with one of:
//
//   - TYPE 0x02 (ACCEPT)  — the SERVICE_NAME we asked for happened to
//     exist; rare for us since we send an empty SERVICE_NAME. The body
//     starts with the negotiated TNS protocol version (uint16 BE).
//   - TYPE 0x04 (REFUSE)  — service not found; body is an ASCII reason
//     string of the form "(ERR=12514)(VSNNUM=318767104)(...)". This is
//     the expected, fingerprint-valid case for our scan: it confirms the
//     listener is up and leaks the precise Oracle release via VSNNUM.
//   - TYPE 0x0B (RESEND)  — the listener wants us to re-issue with
//     different parameters. Treated as detection-only.
//
// Versions are decoded two ways: the TNS protocol version word from the
// ACCEPT body, and the much more useful VSNNUM 32-bit field parsed out
// of the REFUSE body (high byte is the major release: 0x13 → "19.0.0",
// 0x15 → "21.0.0", and so on).
func probeOracleTNS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	descriptor := fmt.Sprintf(
		"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=))(ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d)))",
		target.IP.String(), target.Port,
	)

	packet := buildOracleTNSConnect(descriptor)

	if _, writeErr := conn.Write(packet); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 4096)

	n, err := io.ReadAtLeast(conn, buf, 8)
	if err != nil || n < 8 {
		return nil, errors.New("oracle: short TNS reply")
	}

	pktLen := int(binary.BigEndian.Uint16(buf[0:2]))
	pktType := buf[4]

	if pktLen > 8 && pktLen <= cap(buf) && n < pktLen {
		more, _ := io.ReadAtLeast(conn, buf[n:], pktLen-n)
		n += more
	}

	body := buf[8:n]

	switch pktType {
	case 0x02:
		return oracleResultFromAccept(target, body), nil
	case 0x04:
		return oracleResultFromRefuse(target, body), nil
	case 0x0B:
		return &Result{
			Target:   target,
			Protocol: productOracleTNS,
			Banner:   "Oracle TNS Listener (RESEND)",
			Fingerprint: &FingerprintResult{
				Product: productOracleTNS,
				RawJSON: mustMarshalJSON(map[string]any{
					"packet_type": "RESEND",
					"raw_hex":     hex.EncodeToString(buf[:n]),
				}),
			},
		}, nil
	}

	return &Result{Target: target, Protocol: protocolTCP}, nil
}

// buildOracleTNSConnect assembles a CONNECT packet whose CONNECT_DATA
// region is the supplied descriptor. The fixed body before the descriptor
// is 42 bytes; that puts the descriptor at packet offset 50 (0x0032).
func buildOracleTNSConnect(descriptor string) []byte {
	const fixedBodyLen = 42

	const descriptorOffset = 8 + fixedBodyLen

	totalLen := descriptorOffset + len(descriptor)

	pkt := make([]byte, totalLen)

	binary.BigEndian.PutUint16(pkt[0:2], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[2:4], 0)
	pkt[4] = 0x01
	pkt[5] = 0x00
	binary.BigEndian.PutUint16(pkt[6:8], 0)

	binary.BigEndian.PutUint16(pkt[8:10], 0x013A)
	binary.BigEndian.PutUint16(pkt[10:12], 0x012C)
	binary.BigEndian.PutUint16(pkt[12:14], 0x0C41)
	binary.BigEndian.PutUint16(pkt[14:16], 0x2000)
	binary.BigEndian.PutUint16(pkt[16:18], 0xFFFF)
	binary.BigEndian.PutUint16(pkt[18:20], 0x7F08)
	binary.BigEndian.PutUint16(pkt[20:22], 0)
	binary.BigEndian.PutUint16(pkt[22:24], 0x0100)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(len(descriptor)))
	binary.BigEndian.PutUint16(pkt[26:28], uint16(descriptorOffset))
	binary.BigEndian.PutUint32(pkt[28:32], 0x00000800)
	pkt[32] = 0x41
	pkt[33] = 0x41
	binary.BigEndian.PutUint32(pkt[34:38], 0)
	binary.BigEndian.PutUint32(pkt[38:42], 0)
	binary.BigEndian.PutUint64(pkt[42:50], 0)

	copy(pkt[50:], descriptor)

	return pkt
}

func oracleResultFromAccept(target Target, body []byte) *Result {
	versionWord := uint16(0)

	if len(body) >= 2 {
		versionWord = binary.BigEndian.Uint16(body[0:2])
	}

	version := oracleVersionFromProtocolWord(versionWord)

	return &Result{
		Target:   target,
		Protocol: productOracleTNS,
		Banner:   "Oracle TNS Listener",
		Fingerprint: &FingerprintResult{
			Product: productOracleTNS,
			Version: version,
			RawJSON: mustMarshalJSON(map[string]any{
				"packet_type":  "ACCEPT",
				"version_word": fmt.Sprintf("0x%04x", versionWord),
				"version":      version,
			}),
		},
	}
}

func oracleResultFromRefuse(target Target, body []byte) *Result {
	text := oracleSanitiseRefuseText(body)

	vsnnum, ok := oracleParseVSNNUM(text)
	version := ""

	if ok {
		version = oracleVersionFromVSNNUM(vsnnum)
	}

	errCode := oracleParseERR(text)

	edition := oracleParseServiceHint(text)

	banner := "Oracle TNS Listener"
	if errCode == 12514 {
		banner = "Oracle TNS Listener (ORA-12514 no service)"
	}

	return &Result{
		Target:   target,
		Protocol: productOracleTNS,
		Banner:   banner,
		Fingerprint: &FingerprintResult{
			Product: productOracleTNS,
			Version: version,
			Edition: edition,
			RawJSON: mustMarshalJSON(map[string]any{
				"packet_type": "REFUSE",
				"reason":      text,
				"vsnnum":      vsnnum,
				"err_code":    errCode,
				"version":     version,
			}),
		},
	}
}

// oracleVersionFromProtocolWord maps the TNS protocol version word
// (negotiated in the ACCEPT body) onto the Oracle release family. The
// real Oracle release lives in VSNNUM, so this is only useful for the
// rare ACCEPT case.
func oracleVersionFromProtocolWord(word uint16) string {
	switch word {
	case 0x012C:
		return "10.2"
	case 0x013A:
		return "11.1"
	case 0x013B:
		return "11.2"
	case 0x0142:
		return "12.1"
	case 0x014C:
		return "12.2"
	case 0x0150:
		return "18.0"
	case 0x0154:
		return "19.0"
	case 0x0156:
		return "21.0"
	case 0x0157:
		return "23.0"
	}

	if word == 0 {
		return ""
	}

	return fmt.Sprintf("%d.x", word>>8)
}

// oracleVersionFromVSNNUM converts a VSNNUM 32-bit field into a dotted
// release string. The encoding is one nibble per component:
//
//	byte 0 (MSB)  = major release (decimal value of the byte, not a nibble)
//	byte 1, hi nibble = minor
//	byte 1, lo nibble = revision
//	byte 2 = build / patch level
//	byte 3 = port-specific
//
// Examples observed in the wild:
//
//	318767104 (0x13000000) → "19.0.0"  (19c base)
//	352321536 (0x15000000) → "21.0.0"  (21c base)
//	186646528 (0x0B200200) → "11.2.0.2" (11gR2 11.2.0.2)
func oracleVersionFromVSNNUM(vsnnum uint32) string {
	if vsnnum == 0 {
		return ""
	}

	major := int(vsnnum >> 24)
	minor := int((vsnnum >> 20) & 0xF)
	revision := int((vsnnum >> 16) & 0xF)
	build := int((vsnnum >> 8) & 0xFF)

	if build > 0 {
		return fmt.Sprintf("%d.%d.%d.%d", major, minor, revision, build)
	}

	return fmt.Sprintf("%d.%d.%d", major, minor, revision)
}

var oracleVSNNUMRE = regexp.MustCompile(`(?i)\(VSNNUM\s*=\s*(\d+)\)`)

var oracleERRRE = regexp.MustCompile(`(?i)\(ERR\s*=\s*(-?\d+)\)`)

var oracleServiceHintRE = regexp.MustCompile(`(?i)service\s+["']?([A-Za-z0-9._\-]+)["']?`)

func oracleParseVSNNUM(s string) (uint32, bool) {
	match := oracleVSNNUMRE.FindStringSubmatch(s)
	if len(match) != 2 {
		return 0, false
	}

	n, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil {
		return 0, false
	}

	return uint32(n), true
}

func oracleParseERR(s string) int {
	match := oracleERRRE.FindStringSubmatch(s)
	if len(match) != 2 {
		return 0
	}

	n, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}

	return n
}

// oracleParseServiceHint returns the SERVICE_NAME echoed back in a REFUSE
// body when the listener mentions which service it expected. Many
// installations log the canonical service name verbatim — useful as the
// Edition field.
func oracleParseServiceHint(s string) string {
	match := oracleServiceHintRE.FindStringSubmatch(s)
	if len(match) != 2 {
		return ""
	}

	return strings.TrimSpace(match[1])
}

// oracleSanitiseRefuseText returns the printable portion of a REFUSE
// body. The listener sometimes prefixes the textual reason with a couple
// of control bytes (app/system reason + 16-bit length), so we strip
// non-printable leading bytes before returning.
func oracleSanitiseRefuseText(body []byte) string {
	start := 0

	for start < len(body) && (body[start] < 0x20 || body[start] > 0x7E) {
		start++
	}

	if start >= len(body) {
		return ""
	}

	return strings.TrimRight(string(body[start:]), "\x00 ")
}
