package probe

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

func init() {
	RegisterUDP(probeSNMP, 161)
}

// probeSNMP sends an SNMPv2c GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
// with community string "public" and parses any response.
func probeSNMP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialUDP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial SNMP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	request := snmpGetSysDescr()

	if _, writeErr := conn.Write(request); writeErr != nil {
		return nil, fmt.Errorf("can't write SNMP request: %w", writeErr)
	}

	buf := make([]byte, 2048)

	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("can't read SNMP response: %w", err)
	}

	resp := buf[:n]

	sysDescr := snmpExtractFirstOctetString(resp)

	anonymous := sysDescr != ""

	fp := &FingerprintResult{
		Product:      "snmp",
		Version:      "v2c",
		Anonymous:    anonymous,
		AuthRequired: boolPtr(!anonymous),
		RawJSON: mustMarshalJSON(map[string]any{
			"community":  "public",
			"sys_descr":  sysDescr,
			"raw_hex":    hex.EncodeToString(resp),
			"oid":        "1.3.6.1.2.1.1.1.0",
			"bytes_read": n,
		}),
	}

	if product, version := classifySNMPSysDescr(sysDescr); product != "" {
		fp.Product = product
		if version != "" {
			fp.Version = version
		}
	}

	return &Result{
		Target:      target,
		Protocol:    "snmp",
		Banner:      sysDescr,
		Fingerprint: fp,
	}, nil
}

// snmpSysDescrPattern maps a regexp over the SNMPv2-MIB sysDescr.0 string
// to a cpemap product key (and an optional capture group index for the
// firmware version). NTCIP-compliant traffic controllers, Cisco/MikroTik
// kit and most industrial gateways all spell their own model in sysDescr,
// so a few dozen patterns cover the long tail.
type snmpSysDescrPattern struct {
	re      *regexp.Regexp
	product string
}

// snmpSysDescrPatterns is checked in order; first match wins.
var snmpSysDescrPatterns = []snmpSysDescrPattern{
	// Traffic-signal controllers (NTCIP / ATC platforms).
	{regexp.MustCompile(`(?i)Econolite\s+(?:ASC[\s/]?3|Cobalt)\b[^\n]*?v?([\w.\-]+)?`), "econolite_asc3"},
	{regexp.MustCompile(`(?i)Cobalt\s+v?([\w.\-]+)?`), "econolite_cobalt"},
	{regexp.MustCompile(`(?i)McCain\s+ATC(?:\s+eX)?\s+v?([\w.\-]+)?`), "mccain_atc"},
	{regexp.MustCompile(`(?i)Trafficware\s+(?:Scout|Commander|V8x)\s*v?([\w.\-]+)?`), "trafficware_atc"},
	{regexp.MustCompile(`(?i)Cubic\s+ITS\s+Scout\s*v?([\w.\-]+)?`), "trafficware_atc"},
	{regexp.MustCompile(`(?i)Siemens\s+(?:Sitraffic|SX\s+Traffic\s+Controller|SCALA)\b[^\n]*?v?([\w.\-]+)?`), "siemens_sitraffic"},
	{regexp.MustCompile(`(?i)SWARCO\s+(?:ACTROS|TrafficController)\s*v?([\w.\-]+)?`), "swarco_traffic"},
	{regexp.MustCompile(`(?i)Intelight\s+(?:X1|MaxTime)\s*v?([\w.\-]+)?`), "intelight_x1"},

	// Network gear.
	{regexp.MustCompile(`(?i)Cisco\s+IOS(?:\s+XE)?\s+Software,[^\n]*?Version\s+([\w.\-()]+)`), "cisco_ios"},
	{regexp.MustCompile(`(?i)Cisco\s+Adaptive\s+Security\s+Appliance\s+Version\s+([\w.\-()]+)`), "cisco_asa"},
	{regexp.MustCompile(`(?i)Cisco\s+NX-OS[^\n]*?Version\s+([\w.\-()]+)`), "cisco_nxos"},
	{regexp.MustCompile(`(?i)RouterOS\s+([\w.\-]+)`), "mikrotik_routeros"},                         //nolint:misspell // RouterOS is MikroTik's product name
	{regexp.MustCompile(`(?i)Mikrotik\s+RouterBOARD[^\n]*?ROS\s+([\w.\-]+)`), "mikrotik_routeros"}, //nolint:misspell // RouterOS is MikroTik's product name
	{regexp.MustCompile(`(?i)EdgeOS\s+v?([\w.\-]+)`), "ubiquiti_edgeos"},
	{regexp.MustCompile(`(?i)Juniper\s+Networks[^\n]*?JUNOS\s+([\w.\-]+)`), "juniper_junos"},

	// ICS / building-automation gateways often expose sysDescr too.
	{regexp.MustCompile(`(?i)Tridium\s+(?:Niagara|JACE)[^\n]*?v?([\w.\-]+)`), "tridium_niagara"},
	{regexp.MustCompile(`(?i)Schneider[\s-]Electric[^\n]*?Modicon[^\n]*?v?([\w.\-]+)?`), "schneider_electric_modicon"},
	{regexp.MustCompile(`(?i)Siemens.*?SCALANCE[^\n]*?v?([\w.\-]+)?`), "siemens_simatic"},
	{regexp.MustCompile(`(?i)Honeywell[\s-]?(?:WEBs|Niagara)[^\n]*?v?([\w.\-]+)?`), "tridium_niagara"},
	{regexp.MustCompile(`(?i)Schweitzer[\s-]Engineering[\s-]Laboratories[^\n]*?(?:SEL-3530|RTAC)[^\n]*?v?([\w.\-]+)?`), "sel_rtac"},

	// Smart lighting / EV.
	{regexp.MustCompile(`(?i)Helvar\s+Imagine\s+([\w.\-]+)?`), "helvar_imagine"},
	{regexp.MustCompile(`(?i)KEBA\s+KeContact\s+P[23]0[^\n]*?v?([\w.\-]+)?`), "keba_charger"},

	// Fire-alarm and life-safety panels (most expose a stripped-down
	// SNMPv2c agent for the building-management EMS bridge).
	{regexp.MustCompile(`(?i)NOTIFIER\s+(?:ONYX|NFN)[^\n]*?v?([\w.\-]+)?`), "notifier_onyx"},
	{regexp.MustCompile(`(?i)Siemens.*?Cerberus[\s-]?PRO[^\n]*?v?([\w.\-]+)?`), "siemens_cerberus"},
	{regexp.MustCompile(`(?i)Bosch.*?Avenar[^\n]*?v?([\w.\-]+)?`), "bosch_avenar"},
	{regexp.MustCompile(`(?i)Edwards.*?EST[\s-]?3(?:x)?[^\n]*?v?([\w.\-]+)?`), "edwards_est3"},
	{regexp.MustCompile(`(?i)Simplex\s+4100ES[^\n]*?v?([\w.\-]+)?`), "simplex_4100es"},
	{regexp.MustCompile(`(?i)Schrack[\s-]Seconet\s+Integral[\s-](?:IP|MX)[^\n]*?v?([\w.\-]+)?`), "schrack_seconet"},
	{regexp.MustCompile(`(?i)Autronica\s+(?:AutroPrime|AutroSafe)[^\n]*?v?([\w.\-]+)?`), "autronica_fire"},

	// Access-control / payment-and-pass.
	{regexp.MustCompile(`(?i)Lenel\s+OnGuard[^\n]*?v?([\w.\-]+)?`), "lenel_onguard"},
	{regexp.MustCompile(`(?i)Software\s+House\s+(?:C-CURE|iSTAR)[^\n]*?v?([\w.\-]+)?`), "software_house_ccure"},
	{regexp.MustCompile(`(?i)S2\s+(?:NetBox|Security)[^\n]*?v?([\w.\-]+)?`), "s2_netbox"},
	{regexp.MustCompile(`(?i)Mercury\s+(?:Security|MR\d+|LP\d{4})[^\n]*?v?([\w.\-]+)?`), "hid_mercury"},
	{regexp.MustCompile(`(?i)HID\s+(?:VertX|Edge)\s+EVO[^\n]*?v?([\w.\-]+)?`), "hid_edge"},
	{regexp.MustCompile(`(?i)Gallagher\s+Command\s+Centre[^\n]*?v?([\w.\-]+)?`), "gallagher_command"},
	{regexp.MustCompile(`(?i)Suprema\s+BioStar[\s-]?2[^\n]*?v?([\w.\-]+)?`), "suprema_biostar"},
	{regexp.MustCompile(`(?i)ZKTeco\s+(?:ZKBioSecurity|PushSDK)[^\n]*?v?([\w.\-]+)?`), "zkteco_biosecurity"},
	{regexp.MustCompile(`(?i)Paxton\s+Net2[^\n]*?v?([\w.\-]+)?`), "paxton_net2"},
	{regexp.MustCompile(`(?i)Nedap\s+AEOS[^\n]*?v?([\w.\-]+)?`), "nedap_aeos"},
	{regexp.MustCompile(`(?i)Bolid\s+Orion[\s-]Pro[^\n]*?v?([\w.\-]+)?`), "bolid_orion"},
	{regexp.MustCompile(`(?i)PERCo\s+(?:Web|S-20)[^\n]*?v?([\w.\-]+)?`), "perco_web"},

	// Water/Wastewater + agriculture (when SNMP is enabled on the
	// embedded gateway).
	{regexp.MustCompile(`(?i)Mitsubishi.*?MELSEC[\s-]?(?:iQ-R|iQ-F|Q|L)[^\n]*?v?([\w.\-]+)?`), "mitsubishi_melsec"},
	{regexp.MustCompile(`(?i)Wonderware\s+InTouch[^\n]*?v?([\w.\-]+)?`), "wonderware_intouch"},
	{regexp.MustCompile(`(?i)AVEVA\s+(?:System Platform|InTouch)[^\n]*?v?([\w.\-]+)?`), "wonderware_intouch"},
	{regexp.MustCompile(`(?i)OSIsoft\s+PI[\s-](?:Server|Web\s+API)[^\n]*?v?([\w.\-]+)?`), "osisoft_pi"},
	{regexp.MustCompile(`(?i)Iconics\s+Genesis64[^\n]*?v?([\w.\-]+)?`), "iconics_genesis"},
	{regexp.MustCompile(`(?i)Yokogawa\s+CENTUM\s+VP[^\n]*?v?([\w.\-]+)?`), "yokogawa_centum"},
	{regexp.MustCompile(`(?i)Emerson\s+DeltaV[^\n]*?v?([\w.\-]+)?`), "emerson_deltav"},
	{regexp.MustCompile(`(?i)Hach\s+(?:WIMS|Claros)[^\n]*?v?([\w.\-]+)?`), "hach_wims"},
	{regexp.MustCompile(`(?i)John\s+Deere\s+(?:JDLink|MTG)[^\n]*?v?([\w.\-]+)?`), "john_deere_jdlink"},
	{regexp.MustCompile(`(?i)Trimble\s+(?:Ag\s+Software|TMX-2050)[^\n]*?v?([\w.\-]+)?`), "trimble_ag"},
	{regexp.MustCompile(`(?i)Lindsay\s+FieldNET[^\n]*?v?([\w.\-]+)?`), "lindsay_fieldnet"},
	{regexp.MustCompile(`(?i)Valley\s+(?:ICON|Irrigation)[^\n]*?v?([\w.\-]+)?`), "valley_irrigation"},
	{regexp.MustCompile(`(?i)Rain\s+Bird\s+(?:LNK|ESP-TM2|ESP-Me)[^\n]*?v?([\w.\-]+)?`), "rain_bird_esp"},
	{regexp.MustCompile(`(?i)Hunter\s+(?:Industries|Hydrawise)[^\n]*?v?([\w.\-]+)?`), "hunter_hydrawise"},

	// Printers (some announce JetDirect over SNMP).
	{regexp.MustCompile(`(?i)HP\s+ETHERNET\s+MULTI[\s-]?ENVIRONMENT.*?JetDirect[^\n]*?(\d+\.\d+\.\d+)?`), "jetdirect"},
}

// classifySNMPSysDescr returns the cpemap product key (and optional
// version) that matches a sysDescr response. Empty product means no rule
// recognised the banner.
func classifySNMPSysDescr(sysDescr string) (string, string) {
	if sysDescr == "" {
		return "", ""
	}

	line := strings.ReplaceAll(sysDescr, "\n", " ")

	for _, p := range snmpSysDescrPatterns {
		match := p.re.FindStringSubmatch(line)
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

// snmpGetSysDescr builds a raw SNMPv2c GetRequest for sysDescr.
func snmpGetSysDescr() []byte {
	return []byte{
		0x30, 0x29,
		0x02, 0x01, 0x01,
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x1c,
		0x02, 0x04, 0x00, 0x00, 0x00, 0x42,
		0x02, 0x01, 0x00,
		0x02, 0x01, 0x00,
		0x30, 0x0e,
		0x30, 0x0c,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
		0x05, 0x00,
	}
}

// snmpExtractFirstOctetString walks the BER response and returns the first
// printable OCTET STRING that is longer than the community string.
func snmpExtractFirstOctetString(resp []byte) string {
	i := 0
	for i < len(resp) {
		tag := resp[i]
		i++

		if i >= len(resp) {
			break
		}

		length := int(resp[i])
		i++

		if length&0x80 != 0 {
			lenBytes := length & 0x7f
			if i+lenBytes > len(resp) {
				break
			}

			length = 0

			for j := range lenBytes {
				length = length<<8 | int(resp[i+j])
			}

			i += lenBytes
		}

		if tag == 0x04 && length > 6 {
			if i+length > len(resp) {
				break
			}

			return string(resp[i : i+length])
		}

		if tag&0x20 == 0 || tag == 0xa2 {
			i += length

			continue
		}
	}

	return ""
}
