package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
)

const productKNX = "knx_ip"

func init() {
	RegisterUDP(probeKNX, 3671)
}

// probeKNX issues a KNXnet/IP DESCRIPTION_REQUEST. Replies carry a
// DIB_DEVICE_INFO structure with the KNX serial number, the MAC address and
// — most importantly for us — the KNX manufacturer ID and a 30-byte
// "Friendly Name" the gateway exposes for itself. That's enough to derive a
// product fingerprint for the vast majority of installed gateways: Gira
// X1/HomeServer, Jung, ABB IPS/S, Berker, Siemens N146 / IP S, Eelectron,
// MDT, Theben, Weinzierl, Hager, Lingg & Janke.
//
// References: KNXnet/IP 03/08/02 "Core" v01.05, section 7 — SEARCH and
// DESCRIPTION services. Header is always 6 bytes followed by the service
// payload.
//
// DESCRIPTION_REQUEST (0x0203) layout:
//
//	header        06 10 02 03 00 0E
//	HPAI (8)      08 01  ip(4)  port(2)
//
// DESCRIPTION_RESPONSE (0x0204) carries:
//
//	header        06 10 02 04 ll ll
//	DIB device    54 01 <medium 1> <devStatus 1> <indivAddr 2>
//	              <projID 2> <serial 6> <multicast 4> <mac 6>
//	              <friendlyName 30>
//	... more DIBs (services list, etc.) optional ...
//
// We only parse the device DIB, since later DIBs vary by vendor.
func probeKNX(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	local, ok := conn.LocalAddr().(interface{ String() string })
	_ = local
	_ = ok

	// HPAI: use 0.0.0.0:0 so the gateway responds back over the same
	// 5-tuple we sent from. Compliant with the spec, supported by all
	// gateways since the late 2000s.
	req := []byte{
		0x06, 0x10, 0x02, 0x03, 0x00, 0x0E, // header
		0x08, 0x01, // HPAI length + protocol (UDP/IPv4)
		0x00, 0x00, 0x00, 0x00, // IP
		0x00, 0x00, // port
	}

	if _, writeErr := conn.Write(req); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil || n < 14 {
		return nil, err
	}

	if buf[0] != 0x06 || buf[1] != 0x10 || buf[2] != 0x02 || buf[3] != 0x04 {
		return &Result{Target: target, Protocol: productKNX}, nil
	}

	info, err := parseKNXDeviceDIB(buf[6:n])
	if err != nil {
		return &Result{Target: target, Protocol: productKNX, Banner: "KNXnet/IP"}, nil
	}

	product := productKNX
	if mapped, ok := knxManufacturerMap[info.ManufacturerID]; ok {
		product = mapped
	}

	fp := &FingerprintResult{
		Product: product,
		Edition: info.FriendlyName,
		RawJSON: mustMarshalJSON(map[string]any{
			"manufacturer_id": info.ManufacturerID,
			"serial":          info.Serial,
			"individual_addr": info.IndividualAddr,
			"friendly_name":   info.FriendlyName,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productKNX,
		Banner:      strings.TrimSpace(info.FriendlyName),
		Fingerprint: fp,
	}, nil
}

type knxDeviceInfo struct {
	ManufacturerID uint16
	IndividualAddr uint16
	Serial         string
	FriendlyName   string
}

// parseKNXDeviceDIB walks one DIB_DEVICE_INFO structure. Subsequent DIBs
// (services list, manufacturer, supported services) are not required for
// fingerprinting.
func parseKNXDeviceDIB(payload []byte) (knxDeviceInfo, error) {
	out := knxDeviceInfo{}

	if len(payload) < 54 || payload[1] != 0x01 {
		return out, errors.New("knx: not a device DIB")
	}

	dibLen := int(payload[0])
	if dibLen > len(payload) {
		return out, errors.New("knx: dib length out of range")
	}

	dib := payload[:dibLen]

	out.IndividualAddr = binary.BigEndian.Uint16(dib[4:6])
	out.ManufacturerID = binary.BigEndian.Uint16(dib[8:10])
	out.Serial = formatKNXSerial(dib[10:16])
	out.FriendlyName = strings.TrimRight(string(dib[24:54]), "\x00 ")

	return out, nil
}

func formatKNXSerial(b []byte) string {
	const hex = "0123456789ABCDEF"

	out := make([]byte, 0, 12)

	for _, x := range b {
		out = append(out, hex[x>>4], hex[x&0x0F])
	}

	return string(out)
}

// knxManufacturerMap is the curated subset of the KNX Association member
// registry (https://my.knx.org/en/shop/knx-member) that we have CPE
// coordinates for. Other manufacturer IDs leave the result on the generic
// "knx_ip" key, which still gives cvematch a chance at protocol-stack CVEs
// (e.g. Calimero, Falcon SDK, EIBnet).
var knxManufacturerMap = map[uint16]string{
	0x0001: "siemens_simatic",            // Siemens
	0x0002: "abb_plc",                    // ABB
	0x0004: "albrecht_jung",              // Jung
	0x0005: "bticino",                    // BTicino
	0x0006: "berker",                     // Berker
	0x0007: "gira",                       // Gira
	0x0008: "hager",                      // Hager
	0x0009: "ineselec",                   // Insta
	0x000C: "merten",                     // Merten
	0x000D: "schneider_electric_modicon", // Schneider/Merten
	0x000F: "weinzierl",                  // Weinzierl Engineering
	0x0014: "mdt",                        // MDT technologies
	0x0030: "eelectron",                  // Eelectron
	0x0083: "lingg_janke",                // Lingg&Janke
	0x00B4: "theben",                     // Theben AG
}
