package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"
)

const productENIP = "ethernet_ip"

func init() {
	Register(probeENIP, 44818)
}

// probeENIP issues the EtherNet/IP encapsulation ListIdentity command
// (0x0063) and parses the Identity item out of the response. ListIdentity
// works against any Rockwell/Allen-Bradley, Omron, Schneider, B&R, ABB,
// Phoenix Contact and similar CIP device on the default 44818/TCP port.
//
// Wire format (encapsulation header + reply):
//
//	command         uint16 LE = 0x0063
//	length          uint16 LE
//	sessionHandle   uint32 LE
//	status          uint32 LE
//	senderContext   8 bytes
//	options         uint32 LE
//	itemCount       uint16 LE
//	itemType        uint16 LE = 0x000C  (CIP Identity)
//	itemLength      uint16 LE
//	protoVer        uint16 LE = 1
//	socketAddrFam   uint16 BE
//	socketPort      uint16 BE
//	socketIP        4 bytes BE
//	socketZero      8 bytes
//	vendorID        uint16 LE
//	deviceType      uint16 LE
//	productCode     uint16 LE
//	revision        2 bytes (major, minor)
//	status          uint16 LE
//	serialNumber    uint32 LE
//	nameLen         uint8
//	productName     nameLen bytes
//	state           uint8
//
// CIP CVEs are heavily vendor-specific (Rockwell ControlLogix RCE, Omron
// CJ-series, Schneider EcoStruxure …) so we map vendor IDs and product
// name keywords onto cpemap.productMap keys when we can.
func probeENIP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	// Encapsulation header for ListIdentity — 24 bytes total, no payload.
	req := make([]byte, 24)
	binary.LittleEndian.PutUint16(req[0:2], 0x0063)

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	header := make([]byte, 24)
	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return nil, readErr
	}

	length := binary.LittleEndian.Uint16(header[2:4])
	if length == 0 || length > 1024 {
		return &Result{Target: target, Protocol: productENIP}, nil
	}

	body := make([]byte, length)
	if _, readErr := io.ReadFull(conn, body); readErr != nil {
		return &Result{Target: target, Protocol: productENIP}, nil
	}

	identity, err := parseENIPIdentity(body)
	if err != nil {
		return &Result{Target: target, Protocol: productENIP}, nil
	}

	product := productENIP

	switch identity.VendorID {
	case 0x0001: // Rockwell Automation / Allen-Bradley
		product = "rockwell_logix"
	case 0x002F: // Schneider Electric
		product = "schneider_electric_modicon"
	case 0x002C: // Phoenix Contact
		product = "phoenix_contact_plc"
	case 0x002A: // Omron
		product = "omron_plc"
	case 0x0021: // ABB
		product = "abb_plc"
	}

	revision := strconv.Itoa(int(identity.Major)) + "." + strconv.Itoa(int(identity.Minor))

	fp := &FingerprintResult{
		Product: product,
		Version: revision,
		Edition: identity.ProductName,
		RawJSON: mustMarshalJSON(map[string]any{
			"vendor_id":    identity.VendorID,
			"device_type":  identity.DeviceType,
			"product_code": identity.ProductCode,
			"revision":     revision,
			"product_name": identity.ProductName,
			"serial":       identity.Serial,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productENIP,
		Banner:      strings.TrimSpace(identity.ProductName + " " + revision),
		Fingerprint: fp,
	}, nil
}

type enipIdentity struct {
	VendorID    uint16
	DeviceType  uint16
	ProductCode uint16
	Major       uint8
	Minor       uint8
	Serial      uint32
	ProductName string
}

func parseENIPIdentity(body []byte) (enipIdentity, error) {
	out := enipIdentity{}

	if len(body) < 4 {
		return out, errors.New("enip: body too short for item header")
	}

	itemCount := binary.LittleEndian.Uint16(body[0:2])
	if itemCount == 0 {
		return out, errors.New("enip: no items")
	}

	cursor := 2

	for range itemCount {
		if cursor+4 > len(body) {
			return out, errors.New("enip: truncated item header")
		}

		itemType := binary.LittleEndian.Uint16(body[cursor : cursor+2])
		itemLen := binary.LittleEndian.Uint16(body[cursor+2 : cursor+4])
		cursor += 4

		if cursor+int(itemLen) > len(body) {
			return out, errors.New("enip: truncated item body")
		}

		if itemType == 0x000C {
			return parseCIPIdentityItem(body[cursor : cursor+int(itemLen)])
		}

		cursor += int(itemLen)
	}

	return out, errors.New("enip: no CIP Identity item")
}

func parseCIPIdentityItem(item []byte) (enipIdentity, error) {
	out := enipIdentity{}

	// 2 protoVer + 2 sockFam + 2 sockPort + 4 sockIP + 8 sockZero = 18
	// then 2 vendor + 2 deviceType + 2 productCode + 1 major + 1 minor +
	// 2 status + 4 serial + 1 nameLen = 33 bytes before productName.
	if len(item) < 33 {
		return out, errors.New("cip: identity item too short")
	}

	cursor := 18

	out.VendorID = binary.LittleEndian.Uint16(item[cursor : cursor+2])
	out.DeviceType = binary.LittleEndian.Uint16(item[cursor+2 : cursor+4])
	out.ProductCode = binary.LittleEndian.Uint16(item[cursor+4 : cursor+6])
	out.Major = item[cursor+6]
	out.Minor = item[cursor+7]
	// item[cursor+8 : cursor+10] is status, skip.
	out.Serial = binary.LittleEndian.Uint32(item[cursor+10 : cursor+14])

	nameLen := int(item[cursor+14])
	cursor += 15

	if cursor+nameLen > len(item) {
		return out, errors.New("cip: product name overruns item")
	}

	out.ProductName = strings.TrimRight(string(item[cursor:cursor+nameLen]), "\x00")

	return out, nil
}
