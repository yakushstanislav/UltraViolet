package onvifcmd

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// wsseUsernameTokenHeader returns the inner XML for s:Header (UsernameToken
// with PasswordDigest per OASIS WS-Security Username Token Profile 1.0).
func wsseUsernameTokenHeader(username, password string) (string, error) {
	if username == "" || password == "" {
		return "", errors.New("wsse: empty username or password")
	}

	nonce := make([]byte, 16)

	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	created := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	h := sha1.New()

	if _, err := h.Write(nonce); err != nil {
		return "", err
	}

	if _, err := h.Write([]byte(created)); err != nil {
		return "", err
	}

	if _, err := h.Write([]byte(password)); err != nil {
		return "", err
	}

	passDigest := base64.StdEncoding.EncodeToString(h.Sum(nil))

	var escUser, escCreated strings.Builder

	if err := escapeXMLText(&escUser, username); err != nil {
		return "", err
	}

	if err := escapeXMLText(&escCreated, created); err != nil {
		return "", err
	}

	const (
		passType = `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest`
		nonceEnc = `http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary`
	)

	return `<wsse:Security mustUnderstand="1">` +
		`<wsse:UsernameToken>` +
		`<wsse:Username>` + escUser.String() + `</wsse:Username>` +
		`<wsse:Password Type="` + passType + `">` + passDigest + `</wsse:Password>` +
		`<wsse:Nonce EncodingType="` + nonceEnc + `">` + nonceB64 + `</wsse:Nonce>` +
		`<wsu:Created>` + escCreated.String() + `</wsu:Created>` +
		`</wsse:UsernameToken>` +
		`</wsse:Security>`, nil
}

func escapeXMLText(b *strings.Builder, s string) error {
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		default:
			if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
				return errors.New("wsse: invalid character in string")
			}

			b.WriteRune(r)
		}
	}

	return nil
}

// injectWSSESecurityHeader inserts WS-Security into a SOAP 1.2 envelope that
// uses the s: prefix for http://www.w3.org/2003/05/soap-envelope.
func injectWSSESecurityHeader(soap, username, password string) (string, error) {
	if strings.Contains(soap, "xmlns:wsse=") {
		return soap, nil
	}

	hdr, err := wsseUsernameTokenHeader(username, password)
	if err != nil {
		return "", err
	}

	const wsseDecl = ` xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wsutility-1.0.xsd"`

	idx := strings.Index(soap, "<s:Envelope")
	if idx < 0 {
		return "", errors.New("wsse: missing s:Envelope")
	}

	afterOpen := soap[idx+len("<s:Envelope"):]

	end := strings.IndexByte(afterOpen, '>')
	if end < 0 {
		return "", errors.New("wsse: malformed envelope")
	}

	soap = soap[:idx] + "<s:Envelope" + afterOpen[:end] + wsseDecl + afterOpen[end:]

	const bodyOpen = "<s:Body>"

	pos := strings.Index(soap, bodyOpen)
	if pos < 0 {
		return "", errors.New("wsse: missing s:Body")
	}

	return soap[:pos] + "<s:Header>" + hdr + "</s:Header>" + soap[pos:], nil
}
