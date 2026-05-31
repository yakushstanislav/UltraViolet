// Package onvifparse extracts a small structured subset from ONVIF SOAP XML
// responses for interactive tooling. Parsing is best-effort and may emit warnings.
package onvifparse

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Result is the outcome of parsing an ONVIF SOAP body for a known command.
type Result struct {
	Data     map[string]any
	Warnings []string
}

var (
	reXMLText = func(local string) *regexp.Regexp {
		return regexp.MustCompile(`(?i)<(?:[\w.]+:)?` + local + `>\s*([^<]*?)\s*</(?:[\w.]+:)?` + local + `>`)
	}

	reStreamURI = regexp.MustCompile(`(?i)<(?:[\w.]+:)?Uri>\s*([^<\s]+)\s*</(?:[\w.]+:)?Uri>`)

	reProfileTokenAttr = regexp.MustCompile(`(?i)<(?:[\w.]+:)?Profile\b[^>]*\btoken="([^"]+)"`)

	reVideoSourceTokenAttr = regexp.MustCompile(`(?i)<(?:[\w.]+:)?VideoSource\b[^>]*\btoken="([^"]+)"`)

	reMediaXAddr = regexp.MustCompile(`(?i)<(?:[\w.]+:)?Media\b[^>]*>[\s\S]*?<(?:[\w.]+:)?XAddr>\s*([^<\s]+)\s*</(?:[\w.]+:)?XAddr>`)
)

// Parse extracts structured fields for command from XML body.
func Parse(command, body string) Result {
	if body == "" {
		return Result{}
	}

	out := map[string]any{}

	var warns []string

	switch command {
	case "get_stream_uri", "get_snapshot_uri":
		if u := firstStreamLikeURI(body); u != "" {
			out["uri"] = u

			if host, port, path, ok := splitRTSPURL(u); ok {
				out["rtsp_host"] = host

				if port > 0 {
					out["rtsp_port"] = port
				}

				out["rtsp_path"] = path
			}
		}

		if len(out) == 0 {
			warns = append(warns, "uri_not_found")
		}

		return Result{Data: out, Warnings: warns}
	case "get_device_information":
		mergeXMLField(out, body, "Manufacturer")
		mergeXMLField(out, body, "Model")
		mergeXMLField(out, body, "FirmwareVersion")
		mergeXMLField(out, body, "SerialNumber")
		mergeXMLField(out, body, "HardwareId")

		if len(out) == 0 {
			warns = append(warns, "device_information_fields_not_found")
		}

		return Result{Data: out, Warnings: warns}
	case "get_hostname":
		if m := reXMLText("Name").FindStringSubmatch(body); len(m) == 2 && strings.TrimSpace(m[1]) != "" {
			return Result{Data: map[string]any{"name": strings.TrimSpace(m[1])}}
		}

		return Result{Warnings: []string{"hostname_not_found"}}
	case "get_system_date_and_time":
		if m := reXMLText("DateTimeType").FindStringSubmatch(body); len(m) == 2 && strings.TrimSpace(m[1]) != "" {
			out["date_time_type"] = strings.TrimSpace(m[1])
		}

		if m := reXMLText("DaylightSavings").FindStringSubmatch(body); len(m) == 2 {
			out["daylight_savings"] = strings.EqualFold(strings.TrimSpace(m[1]), "true")
		}

		if m := reXMLText("TZ").FindStringSubmatch(body); len(m) == 2 && strings.TrimSpace(m[1]) != "" {
			out["tz"] = strings.TrimSpace(m[1])
		}

		if len(out) == 0 {
			warns = append(warns, "system_date_time_fields_not_found")
		}

		return Result{Data: out, Warnings: warns}
	case "get_capabilities":
		if m := reMediaXAddr.FindStringSubmatch(body); len(m) == 2 {
			out["media_xaddr"] = strings.TrimSpace(m[1])
		} else {
			warns = append(warns, "media_xaddr_not_found")
		}

		return Result{Data: out, Warnings: warns}
	case "get_media_profiles":
		toks := reProfileTokenAttr.FindAllStringSubmatch(body, -1)
		if len(toks) == 0 {
			return Result{Warnings: []string{"profiles_not_found"}}
		}

		profiles := make([]map[string]string, 0, len(toks))

		tokens := make([]string, 0, len(toks))

		seen := make(map[string]struct{}, len(toks))

		for _, m := range toks {
			if len(m) != 2 {
				continue
			}

			t := strings.TrimSpace(m[1])
			if t == "" {
				continue
			}

			if _, ok := seen[t]; ok {
				continue
			}

			seen[t] = struct{}{}

			tokens = append(tokens, t)

			profiles = append(profiles, map[string]string{"token": t})
		}

		out["profiles"] = profiles
		out["profile_tokens"] = tokens

		return Result{Data: out, Warnings: warns}
	case "get_video_sources":
		toks := reVideoSourceTokenAttr.FindAllStringSubmatch(body, -1)
		if len(toks) == 0 {
			return Result{Warnings: []string{"video_sources_not_found"}}
		}

		srcs := make([]map[string]string, 0, len(toks))

		seen := make(map[string]struct{}, len(toks))

		for _, m := range toks {
			if len(m) != 2 {
				continue
			}

			t := strings.TrimSpace(m[1])
			if t == "" {
				continue
			}

			if _, ok := seen[t]; ok {
				continue
			}

			seen[t] = struct{}{}

			srcs = append(srcs, map[string]string{"token": t})
		}

		out["video_sources"] = srcs

		return Result{Data: out, Warnings: warns}
	default:
		return Result{}
	}
}

func mergeXMLField(dst map[string]any, body, local string) {
	re := reXMLText(local)

	if m := re.FindStringSubmatch(body); len(m) == 2 {
		v := strings.TrimSpace(m[1])
		if v != "" {
			dst[strings.ToLower(local)] = v
		}
	}
}

func firstStreamLikeURI(body string) string {
	if m := reStreamURI.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}

	if idx := strings.Index(strings.ToLower(body), "rtsp://"); idx >= 0 {
		rest := body[idx:]
		end := len(rest)

		for i, r := range rest {
			if r == '<' || r == '"' || r == '\'' || r == ' ' || r == '\n' || r == '\r' || r == '\t' {
				end = i

				break
			}
		}

		if end > 0 {
			return strings.TrimSpace(rest[:end])
		}
	}

	return ""
}

func splitRTSPURL(raw string) (host string, port uint16, path string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || !strings.EqualFold(u.Scheme, "rtsp") {
		return "", 0, "", false
	}

	host = u.Hostname()

	p := u.Port()
	if p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return "", 0, "", false
		}

		port = uint16(n)
	}

	path = u.EscapedPath()
	if path == "" {
		path = "/"
	}

	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	return host, port, path, host != ""
}
