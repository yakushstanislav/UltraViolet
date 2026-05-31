package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
)

const productBACnet = "bacnet"

func init() {
	RegisterUDP(probeBACnet, 47808)
}

// probeBACnet sends an unconfirmed BACnet/IP Read-Property request for the
// Vendor-Identifier (75) of the local Device object instance 4194303 (the
// special "this device" value). Devices that follow the spec reply with
// their numeric vendor id; many also offer Vendor-Name (121) and
// Firmware-Revision (44) which we ask for opportunistically.
//
// Wire format:
//
//	BVLC      type=0x81 func=0x0A length=BE16
//	NPDU      version=0x01 control=0x04 (expecting reply)
//	APDU      pduType=0x00 (confirmed) tag=0x05 maxResp=0x04
//	          invokeID=0x01 service=0x0C (ReadProperty)
//	          context tag 0 — objectIdentifier (device,4194303)
//	          context tag 1 — propertyIdentifier (75 = Vendor-Identifier)
//
// References: ASHRAE 135-2020, clause 13 and Annex J.
//
// The reply is parsed loosely — we only pluck out the property value and
// surface it as Vendor-Identifier. Mapping numeric vendor IDs to product
// keys is delegated to bacnetVendor.
func probeBACnet(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	req := []byte{
		0x81, 0x0A, 0x00, 0x11, // BVLC: original-unicast-NPDU, length 0x11=17
		0x01, 0x04, // NPDU: version 1, expecting reply
		0x00,       // APDU: confirmed-request, no segments
		0x05, 0x01, // max-segs / max-resp + invoke ID
		0x0C,                         // ReadProperty service choice
		0x0C, 0x02, 0x3F, 0xFF, 0xFF, // objectIdentifier (device, 4194303)
		0x19, 0x4B, // propertyIdentifier 75 = Vendor-Identifier
	}

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil, err
	}

	if buf[0] != 0x81 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length > n {
		length = n
	}

	vendorID, err := parseBACnetVendorID(buf[:length])
	if err != nil {
		// Not a successful Read-Property reply, but it's still BACnet.
		return &Result{
			Target:   target,
			Protocol: productBACnet,
			Banner:   "BACnet/IP device",
		}, nil
	}

	product := productBACnet
	if mapped, ok := bacnetVendorMap[vendorID]; ok {
		product = mapped
	}

	fp := &FingerprintResult{
		Product: product,
		RawJSON: mustMarshalJSON(map[string]any{
			"vendor_id": vendorID,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productBACnet,
		Banner:      "BACnet vendor=" + strings.ToValidUTF8(strings.ToLower(itoa(int(vendorID))), ""),
		Fingerprint: fp,
	}, nil
}

// parseBACnetVendorID scans a Read-Property-ACK APDU for the Vendor-Identifier
// value. Returns the integer encoded after the application-tag 2 (unsigned
// int) inside the property value container (open=3E, close=3F).
//
// The parser is permissive: we look for the 0x3E … 0x3F bracket, then the
// first unsigned-int application tag inside it.
func parseBACnetVendorID(packet []byte) (uint16, error) {
	open := -1

	for i, b := range packet {
		if b == 0x3E {
			open = i

			break
		}
	}

	if open < 0 || open+1 >= len(packet) {
		return 0, errors.New("bacnet: no property value container")
	}

	for i := open + 1; i < len(packet); i++ {
		if packet[i] == 0x3F {
			break
		}

		// Application tag for unsigned int has tag number 2 → first
		// nibble = 0x2. Length is the low nibble.
		if packet[i]&0xF0 != 0x20 {
			continue
		}

		valueLen := int(packet[i] & 0x0F)
		if valueLen == 0 || valueLen > 4 || i+1+valueLen > len(packet) {
			return 0, errors.New("bacnet: malformed unsigned tag")
		}

		var v uint32

		for k := range valueLen {
			v = (v << 8) | uint32(packet[i+1+k])
		}

		return uint16(v), nil
	}

	return 0, errors.New("bacnet: no unsigned value inside property")
}

// bacnetVendorMap is a curated subset of the ASHRAE BACnet vendor registry
// — only the IDs we have a corresponding cpemap.productMap key for. Adding
// rows here is mechanical: pick the vendor ID from
// http://www.bacnet.org/VendorID/BACnet%20Vendor%20IDs.htm and map onto an
// existing productMap key.
var bacnetVendorMap = map[uint16]string{
	0:   productBACnet,           // ASHRAE
	2:   "honeywell_bacnet",      // Honeywell International
	3:   "siemens_simatic",       // Siemens Building Tech
	5:   "johnson_controls",      // Johnson Controls
	7:   "trane_bacnet",          // Trane
	8:   "delta_controls_bacnet", // Delta Controls
	10:  "schneider_electric_modicon",
	24:  "abb_plc",
	42:  "kmc_controls",
	49:  "tridium_niagara",
	56:  "automatedlogic_bacnet",
	112: "siemens_simatic",      // Siemens Industrial Automation Systems
	260: "kieback_peter_bacnet", // Kieback&Peter
}

// itoa is a stdlib-free integer-to-string for one call site. Avoids
// strconv import bloat in this file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	const digits = "0123456789"

	var buf [12]byte

	i := len(buf)

	neg := n < 0
	if neg {
		n = -n
	}

	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}

	if neg {
		i--
		buf[i] = '-'
	}

	return string(buf[i:])
}
