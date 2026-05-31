package probe

import (
	"net/http"
	"strconv"
	"strings"
)

// extractHTTPSecurity parses the standard HTTP security response headers
// out of a flattened map. Returns nil only when every header is absent —
// callers can use that to skip persistence entirely.
func extractHTTPSecurity(headers map[string]string) *HTTPSecurity {
	if len(headers) == 0 {
		return nil
	}

	sec := &HTTPSecurity{}
	touched := false

	if v := headers["Strict-Transport-Security"]; v != "" {
		parseHSTS(v, sec)

		touched = true
	}

	if v := headers["Content-Security-Policy"]; v != "" {
		parseCSP(v, sec)

		touched = true
	}

	if v := headers["X-Frame-Options"]; v != "" {
		sec.XFrameOptions = strings.TrimSpace(v)

		touched = true
	}

	if v := headers["X-Content-Type-Options"]; v != "" {
		sec.XContentTypeOptions = strings.TrimSpace(v)

		touched = true
	}

	if v := headers["Referrer-Policy"]; v != "" {
		sec.ReferrerPolicy = strings.TrimSpace(v)

		touched = true
	}

	if v := headers["Permissions-Policy"]; v != "" {
		sec.PermissionsPolicyPresent = true

		touched = true
	}

	if v := headers["Access-Control-Allow-Origin"]; v != "" {
		sec.CORSAllowOrigin = strings.TrimSpace(v)

		touched = true
	}

	if v := headers["Set-Cookie"]; v != "" {
		countCookieFlags(v, sec)

		touched = true
	}

	if !touched {
		return nil
	}

	return sec
}

// parseHSTS extracts max-age, includeSubDomains and preload from a
// Strict-Transport-Security header value. Tokens are separated by ';';
// directives and values are case-insensitive per RFC 6797 §6.1.
func parseHSTS(value string, sec *HTTPSecurity) {
	for _, raw := range strings.Split(value, ";") {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}

		lower := strings.ToLower(token)

		switch {
		case strings.HasPrefix(lower, "max-age"):
			eq := strings.IndexByte(token, '=')
			if eq <= 0 {
				continue
			}

			num := strings.Trim(strings.TrimSpace(token[eq+1:]), `"`)
			if n, err := strconv.ParseInt(num, 10, 64); err == nil && n >= 0 {
				sec.HSTSMaxAge = n
			}

		case lower == "includesubdomains":
			sec.HSTSIncludeSubdomains = true

		case lower == "preload":
			sec.HSTSPreload = true
		}
	}
}

// parseCSP records presence flags for the dangerous expressions
// 'unsafe-inline' and 'unsafe-eval'. A full directive walk would be
// overkill — these two flags drive the bulk of CSP-related grading.
func parseCSP(value string, sec *HTTPSecurity) {
	sec.CSPPresent = true

	lower := strings.ToLower(value)

	if strings.Contains(lower, "'unsafe-inline'") {
		sec.CSPHasUnsafeInline = true
	}

	if strings.Contains(lower, "'unsafe-eval'") {
		sec.CSPHasUnsafeEval = true
	}
}

// countCookieFlags walks a comma/newline-joined Set-Cookie value and
// tallies how many cookies carry Secure, HttpOnly and which SameSite
// variant they request. The header map from httpRequest already joins
// duplicates with ", ", so we split on ", " followed by the start of a
// fresh cookie name=value pair to avoid splitting inside Expires=Sat, 12
// Jan… values.
func countCookieFlags(joined string, sec *HTTPSecurity) {
	for _, cookie := range splitSetCookieHeaders(joined) {
		lower := strings.ToLower(cookie)

		if cookieFlagPresent(lower, "secure") {
			sec.CookieSecureCount++
		}

		if cookieFlagPresent(lower, "httponly") {
			sec.CookieHTTPOnlyCount++
		}

		switch cookieFlagValue(lower, "samesite") {
		case "strict":
			sec.CookieSameSiteStrict++
		case "lax":
			sec.CookieSameSiteLax++
		case "none":
			sec.CookieSameSiteNone++
		}
	}
}

// splitSetCookieHeaders splits a flattened Set-Cookie value into its
// individual cookies. Because the Headers map joins duplicates with
// ", ", and Expires= can contain a comma, we re-parse via the standard
// library cookie reader.
func splitSetCookieHeaders(joined string) []string {
	// Use net/http.Header.Values via a stub request to leverage stdlib
	// parsing. Cheaper than re-implementing the date-aware splitter.
	header := http.Header{}
	header.Add("Set-Cookie", joined)

	resp := &http.Response{Header: header}

	cookies := resp.Cookies()

	out := make([]string, 0, len(cookies))

	for _, c := range cookies {
		out = append(out, c.Raw)
	}

	return out
}

// cookieFlagPresent reports whether the cookie attribute list contains
// the given flag as a standalone attribute (semicolon-separated).
func cookieFlagPresent(lowerCookie, flag string) bool {
	for _, raw := range strings.Split(lowerCookie, ";") {
		if strings.TrimSpace(raw) == flag {
			return true
		}
	}

	return false
}

// cookieFlagValue returns the value of a key=value cookie attribute, or
// "" when absent. Returned value is lower-cased and trimmed.
func cookieFlagValue(lowerCookie, key string) string {
	for _, raw := range strings.Split(lowerCookie, ";") {
		token := strings.TrimSpace(raw)

		eq := strings.IndexByte(token, '=')
		if eq <= 0 {
			continue
		}

		if strings.TrimSpace(token[:eq]) != key {
			continue
		}

		return strings.TrimSpace(token[eq+1:])
	}

	return ""
}
