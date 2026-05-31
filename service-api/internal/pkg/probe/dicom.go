package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

const productDICOM = "dicom"

func init() {
	// 104 — legacy IANA assignment kept by older PACS gateways.
	// 11112 — current de-facto DICOM upper layer port (IHE PIX/PDQ,
	// dcm4chee, Orthanc, Conquest, ClearCanvas, DCMTK).
	Register(probeDICOM, 104, 11112)
}

// probeDICOM opens an A-ASSOCIATE-RQ DICOM PDU on the target and inspects
// the reply for an A-ASSOCIATE-AC / A-ASSOCIATE-RJ frame.
//
// PDU layout (DICOM PS3.8, section 9):
//
//	01 00                  (PDU type 0x01 = A-ASSOCIATE-RQ, reserved)
//	<length 4B BE>         (total PDU length)
//	00 01                  (Protocol version)
//	00 00                  (Reserved)
//	16B Called  AE Title   (ASCII space-padded "ANY-SCP         ")
//	16B Calling AE Title   (ASCII space-padded "UltraViolet     ")
//	8B  Reserved zeros
//	    Variable items:
//	      10  Application Context Item (1.2.840.10008.3.1.1.1)
//	      20  Presentation Context Item
//	      50  User Information Item (MaxLength + impl class UID)
//
// A conforming SCP responds with PDU type 0x02 (A-ASSOCIATE-AC) or 0x03
// (A-ASSOCIATE-RJ). Both prove DICOM is up; the AC variant additionally
// exposes the Implementation Class UID and Version Name in the User
// Information sub-item, which we surface when present.
func probeDICOM(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	pdu := buildDICOMAssociateRQ("ANY-SCP", "UltraViolet")

	if _, writeErr := conn.Write(pdu); writeErr != nil {
		return nil, writeErr
	}

	buf := make([]byte, 4096)

	n, err := io.ReadAtLeast(conn, buf, 6)
	if err != nil || n < 6 {
		return nil, errors.New("dicom: short reply")
	}

	pduType := buf[0]
	pduLen := int(binary.BigEndian.Uint32(buf[2:6]))

	if pduType != 0x02 && pduType != 0x03 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	if pduLen > 0 && n < 6+pduLen {
		// Best-effort read of the rest; ignore short reads.
		extra := 6 + pduLen - n
		if extra > len(buf)-n {
			extra = len(buf) - n
		}

		if extra > 0 {
			more, _ := io.ReadAtLeast(conn, buf[n:n+extra], 1)
			n += more
		}
	}

	implClassUID, implVersion := parseDICOMUserInfo(buf[:n])

	banner := "DICOM A-ASSOCIATE"
	if pduType == 0x03 {
		banner = "DICOM A-ASSOCIATE-RJ"
	}

	fp := &FingerprintResult{
		Product: productDICOM,
		Edition: implClassUID,
		Version: implVersion,
		RawJSON: mustMarshalJSON(map[string]any{
			"pdu_type":       pduType,
			"impl_class_uid": implClassUID,
			"impl_version":   implVersion,
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productDICOM,
		Banner:      banner,
		Fingerprint: fp,
	}, nil
}

// buildDICOMAssociateRQ assembles a minimal A-ASSOCIATE-RQ PDU declaring
// the Verification SOP Class (1.2.840.10008.1.1) over Implicit VR Little
// Endian transfer syntax. Just enough to elicit an AC or RJ.
func buildDICOMAssociateRQ(called, calling string) []byte {
	const (
		appCtxUID       = "1.2.840.10008.3.1.1.1"
		verificationUID = "1.2.840.10008.1.1"
		implicitVRUID   = "1.2.840.10008.1.2"
		implClassUID    = "1.2.826.0.1.3680043.2.1143.107.104.103.115.0.1.0"
		implVersion     = "ULTRAVIOLET_0.1"
	)

	appCtx := dicomSubItem(0x10, []byte(appCtxUID))

	abstractSyntax := dicomSubItem(0x30, []byte(verificationUID))
	transferSyntax := dicomSubItem(0x40, []byte(implicitVRUID))

	presCtxBody := make([]byte, 0, 4+len(abstractSyntax)+len(transferSyntax))
	presCtxBody = append(presCtxBody, 0x01, 0x00, 0x00, 0x00)
	presCtxBody = append(presCtxBody, abstractSyntax...)
	presCtxBody = append(presCtxBody, transferSyntax...)
	presCtx := dicomSubItem(0x20, presCtxBody)

	maxLen := []byte{0x51, 0x00, 0x00, 0x04, 0x00, 0x00, 0x40, 0x00}
	implClass := dicomSubItem(0x52, []byte(implClassUID))
	implVer := dicomSubItem(0x55, []byte(implVersion))

	userInfoBody := append([]byte{}, maxLen...)
	userInfoBody = append(userInfoBody, implClass...)
	userInfoBody = append(userInfoBody, implVer...)
	userInfo := dicomSubItem(0x50, userInfoBody)

	variable := make([]byte, 0, len(appCtx)+len(presCtx)+len(userInfo))
	variable = append(variable, appCtx...)
	variable = append(variable, presCtx...)
	variable = append(variable, userInfo...)

	header := make([]byte, 0, 68)
	header = append(header, 0x00, 0x01)
	header = append(header, 0x00, 0x00)
	header = append(header, padAETitle(called)...)
	header = append(header, padAETitle(calling)...)
	header = append(header, make([]byte, 32)...)

	body := append(header, variable...)

	pdu := make([]byte, 6, 6+len(body))
	pdu[0] = 0x01
	pdu[1] = 0x00

	binary.BigEndian.PutUint32(pdu[2:6], uint32(len(body)))

	return append(pdu, body...)
}

// dicomSubItem wraps payload in the DICOM variable-item header.
func dicomSubItem(itemType byte, payload []byte) []byte {
	out := make([]byte, 4, 4+len(payload))
	out[0] = itemType
	out[1] = 0x00

	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))

	return append(out, payload...)
}

// padAETitle returns a 16-byte space-padded Application Entity title.
func padAETitle(title string) []byte {
	out := make([]byte, 16)

	for i := range 16 {
		out[i] = ' '
	}

	for i, c := range []byte(title) {
		if i >= 16 {
			break
		}

		out[i] = c
	}

	return out
}

// parseDICOMUserInfo walks an A-ASSOCIATE-AC/RJ PDU looking for the User
// Information sub-item (0x50) and inside it the Implementation Class UID
// (0x52) and Version Name (0x55). Empty strings on failure.
func parseDICOMUserInfo(pdu []byte) (string, string) {
	if len(pdu) < 6 {
		return "", ""
	}

	// Skip the 6-byte PDU header and the 68-byte fixed A-ASSOCIATE
	// preamble (versions / reserved / called AE / calling AE / 32B).
	if len(pdu) < 74 {
		return "", ""
	}

	body := pdu[74:]

	for len(body) >= 4 {
		itemType := body[0]
		itemLen := int(binary.BigEndian.Uint16(body[2:4]))

		if itemLen+4 > len(body) {
			return "", ""
		}

		payload := body[4 : 4+itemLen]
		body = body[4+itemLen:]

		if itemType != 0x50 {
			continue
		}

		return parseDICOMUserInfoBody(payload)
	}

	return "", ""
}

// parseDICOMUserInfoBody extracts the Implementation Class UID (0x52) and
// Implementation Version Name (0x55) from a User Information item body.
func parseDICOMUserInfoBody(body []byte) (string, string) {
	var (
		implClass   string
		implVersion string
	)

	for len(body) >= 4 {
		subType := body[0]
		subLen := int(binary.BigEndian.Uint16(body[2:4]))

		if subLen+4 > len(body) {
			break
		}

		value := strings.TrimRight(string(body[4:4+subLen]), "\x00 ")
		body = body[4+subLen:]

		switch subType {
		case 0x52:
			implClass = value
		case 0x55:
			implVersion = value
		}
	}

	return implClass, implVersion
}
