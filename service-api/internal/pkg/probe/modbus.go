package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const productModbus = "modbus"

func init() {
	Register(probeModbus, 502)
}

// probeModbus issues the Modbus TCP "Read Device Identification" request
// (FC 0x2B / MEI 0x0E, code 0x01 = basic device id) and parses the standard
// Vendor / ProductCode / Revision objects out of the reply.
//
// Background: this is the only Modbus call that requires no register list
// up-front and is supported by virtually every PLC sold this decade
// (Schneider, Siemens, Rockwell, Wago, B&R, Phoenix Contact…). Anything
// older than that simply returns an exception (0x80 + FC + ExceptionCode)
// and we still mark the protocol as "modbus" without a fingerprint.
//
// Wire format reference:
//
//	MBAP header  TXID(2) PROTOID(2)=0 LEN(2) UNITID(1)
//	PDU          FC(1)=0x2B MEI(1)=0x0E READID(1)=0x01 OBJID(1)=0x00
//
// Reply PDU (success):
//
//	FC(1)=0x2B MEI(1)=0x0E READID(1) CONFORM(1) MOREFOLLOWS(1)
//	NEXTOBJID(1) NUMOBJECTS(1)
//	[ OBJID(1) LEN(1) DATA(N) ]*
//
// Object IDs we care about:
//
//	0x00 VendorName
//	0x01 ProductCode
//	0x02 MajorMinorRevision
func probeModbus(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	req := []byte{
		0x00, 0x01, // TXID
		0x00, 0x00, // ProtoID = 0
		0x00, 0x05, // Length = 5 bytes after this
		0xFF, // Unit ID — broadcast-style, accepted by most PLCs
		0x2B, // FC = 43 (Encapsulated Interface Transport)
		0x0E, // MEI Type = 14 (Read Device Identification)
		0x01, // Read Device ID code = basic
		0x00, // Object ID = 0 (start at VendorName)
	}

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	header := make([]byte, 7)
	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return &Result{Target: target, Protocol: productModbus}, nil
	}

	bodyLen := int(binary.BigEndian.Uint16(header[4:6])) - 1
	if bodyLen <= 0 || bodyLen > 256 {
		return &Result{Target: target, Protocol: productModbus}, nil
	}

	body := make([]byte, bodyLen)
	if _, readErr := io.ReadFull(conn, body); readErr != nil {
		return &Result{Target: target, Protocol: productModbus}, nil
	}

	objects, err := parseModbusDeviceID(body)
	if err != nil || len(objects) == 0 {
		return &Result{Target: target, Protocol: productModbus}, nil
	}

	vendor := strings.TrimSpace(objects[0x00])
	productCode := strings.TrimSpace(objects[0x01])
	revision := strings.TrimSpace(objects[0x02])

	product := productModbus
	// Map known vendor strings onto cpemap.productMap keys so cvematch
	// pulls vendor-specific CVEs. Falls back to plain "modbus" when the
	// vendor token isn't recognised.
	switch {
	case containsFold(vendor, "schneider"):
		product = "schneider_electric_modicon"
	case containsFold(vendor, "siemens"):
		product = "siemens_simatic"
	case containsFold(vendor, "rockwell"), containsFold(vendor, "allen-bradley"):
		product = "rockwell_logix"
	case containsFold(vendor, "wago"):
		product = "wago_plc"
	case containsFold(vendor, "phoenix"):
		product = "phoenix_contact_plc"
	}

	fp := &FingerprintResult{
		Product: product,
		Version: revision,
		Edition: productCode,
		RawJSON: mustMarshalJSON(map[string]any{
			"vendor":       vendor,
			"product_code": productCode,
			"revision":     revision,
		}),
	}

	banner := vendor
	if productCode != "" {
		banner += " " + productCode
	}

	if revision != "" {
		banner += " " + revision
	}

	return &Result{
		Target:      target,
		Protocol:    productModbus,
		Banner:      strings.TrimSpace(banner),
		Fingerprint: fp,
	}, nil
}

// parseModbusDeviceID walks the FC=0x2B reply PDU and returns a map
// {objectID -> string}. The minimum sensible payload is the 7-byte header
// followed by at least one object (id+len+data >= 2 bytes).
func parseModbusDeviceID(body []byte) (map[byte]string, error) {
	if len(body) < 7 {
		return nil, errors.New("modbus: pdu too short")
	}

	if body[0] != 0x2B || body[1] != 0x0E {
		return nil, errors.New("modbus: unexpected FC/MEI")
	}

	numObjects := int(body[6])
	cursor := 7
	out := make(map[byte]string, numObjects)

	for i := 0; i < numObjects && cursor+2 <= len(body); i++ {
		objID := body[cursor]
		objLen := int(body[cursor+1])
		cursor += 2

		if cursor+objLen > len(body) {
			break
		}

		out[objID] = string(body[cursor : cursor+objLen])
		cursor += objLen
	}

	return out, nil
}

// containsFold is strings.Contains with case folding, kept local so probes
// don't grow a dependency on a "stringsutil" helper for one call site.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
