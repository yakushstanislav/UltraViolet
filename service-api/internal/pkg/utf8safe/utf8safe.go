// Package utf8safe normalizes arbitrary byte-derived strings for PostgreSQL UTF-8 text columns.
package utf8safe

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const replacement = "\uFFFD"

// Sanitize returns s safe for PostgreSQL UTF-8 text columns: invalid UTF-8 sequences and
// U+0000 runes are replaced with the Unicode replacement character.
func Sanitize(s string) string {
	s = strings.ToValidUTF8(s, replacement)

	if strings.IndexByte(s, 0) < 0 {
		return s
	}

	return strings.ReplaceAll(s, "\x00", replacement)
}

// SanitizeStrings returns a copy of ss with Sanitize applied to each element.
func SanitizeStrings(ss []string) []string {
	if len(ss) == 0 {
		return ss
	}

	out := make([]string, len(ss))

	for i, s := range ss {
		out[i] = Sanitize(s)
	}

	return out
}

// SanitizeMapString returns a shallow copy of m with Sanitize applied to each key and value.
func SanitizeMapString(m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}

	out := make(map[string]string, len(m))

	for k, v := range m {
		out[Sanitize(k)] = Sanitize(v)
	}

	return out
}

// SanitizeBytes returns b unchanged when it is valid UTF-8; otherwise it applies Sanitize to the
// string view of b (replacing invalid sequences) and returns the resulting bytes.
func SanitizeBytes(b []byte) []byte {
	if len(b) == 0 {
		return b
	}

	if utf8.Valid(b) {
		return b
	}

	return []byte(Sanitize(string(b)))
}

// SanitizeJSONB returns JSON bytes safe to assign to PostgreSQL json/jsonb. Decoded JSON
// strings must not contain U+0000: PostgreSQL rejects the \u0000 escape when parsing
// JSON into text (see “unsupported Unicode escape sequence”). Typical source is
// json.Marshal of a Go string that held binary HTTP body bytes.
//
// Valid JSON is round-tripped through encoding/json so NUL runes are replaced and the
// document is re-encoded. When unmarshalling fails, b is returned unchanged (still after
// SanitizeBytes) so non-JSON payloads are not rewritten.
func SanitizeJSONB(b []byte) []byte {
	b = SanitizeBytes(b)
	if len(b) == 0 {
		return b
	}

	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return b
	}

	v = sanitizeJSONValue(v)

	out, err := json.Marshal(v)
	if err != nil {
		return b
	}

	return out
}

func sanitizeJSONValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case bool, float64, json.Number:
		return t
	case string:
		return sanitizeJSONString(t)
	case []any:
		for i, x := range t {
			t[i] = sanitizeJSONValue(x)
		}

		return t
	case map[string]any:
		out := make(map[string]any, len(t))

		for k, val := range t {
			out[sanitizeJSONString(k)] = sanitizeJSONValue(val)
		}

		return out
	default:
		return t
	}
}

func sanitizeJSONString(s string) string {
	return Sanitize(s)
}
