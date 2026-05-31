package probe

import (
	"context"
	"fmt"
	"strings"
)

func init() {
	Register(probeLDAP, 389)
}

// probeLDAP sends an LDAP anonymous bind (BindRequest version 3, empty
// name+credentials) and reports whether the server accepted it.
func probeLDAP(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial LDAP target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	bindRequest := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x60, 0x07,
		0x02, 0x01, 0x03,
		0x04, 0x00,
		0x80, 0x00,
	}

	if _, writeErr := conn.Write(bindRequest); writeErr != nil {
		return nil, fmt.Errorf("can't write LDAP bind: %w", writeErr)
	}

	resp := make([]byte, 256)

	n, err := conn.Read(resp)
	if err != nil || n < 14 {
		return nil, fmt.Errorf("can't read LDAP bind response: %w", err)
	}

	resultCode := byte(0xff)

	for i := 0; i+6 < n; i++ {
		if resp[i] == 0x61 && i+4 < n && resp[i+2] == 0x0a && resp[i+3] == 0x01 {
			resultCode = resp[i+4]

			break
		}
	}

	anonymousAllowed := resultCode == 0x00
	authRequired := !anonymousAllowed
	hexBody := strings.ToLower(ldapBytesToHex(resp[:n]))

	return &Result{
		Target:   target,
		Protocol: "ldap",
		Fingerprint: &FingerprintResult{
			Product:      "ldap",
			AuthRequired: &authRequired,
			Anonymous:    anonymousAllowed,
			RawJSON: mustMarshalJSON(map[string]any{
				"bind_result_code":  resultCode,
				"bind_result_name":  ldapResultCodeName(resultCode),
				"anonymous_allowed": anonymousAllowed,
				"raw_hex":           hexBody,
			}),
		},
	}, nil
}

func ldapBytesToHex(in []byte) string {
	const hex = "0123456789abcdef"

	out := make([]byte, len(in)*2)

	for i, b := range in {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}

	return string(out)
}

func ldapResultCodeName(code byte) string {
	switch code {
	case 0:
		return "success"
	case 1:
		return "operationsError"
	case 2:
		return "protocolError"
	case 7:
		return "authMethodNotSupported"
	case 8:
		return "strongerAuthRequired"
	case 32:
		return "noSuchObject"
	case 48:
		return "inappropriateAuthentication"
	case 49:
		return "invalidCredentials"
	case 50:
		return "insufficientAccessRights"
	case 53:
		return "unwillingToPerform"
	}

	return "code_" + telnetByteHex(code)
}
