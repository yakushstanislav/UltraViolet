package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	productONVIF             = "onvif"
	onvifDevicePath          = "/onvif/device_service"
	onvifGetSystemDateAction = "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"
	onvifResponseLimit       = 64 * 1024
)

// onvifGetSystemDateAndTimeSOAP is the smallest valid SOAP 1.2 envelope for
// GetSystemDateAndTime — an unauthenticated ONVIF Device Service operation
// that every compliant responder implements.
const onvifGetSystemDateAndTimeSOAP = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
	` xmlns:tds="http://www.onvif.org/ver10/device/wsdl">` +
	`<s:Body><tds:GetSystemDateAndTime/></s:Body></s:Envelope>`

// probeONVIF POSTs the GetSystemDateAndTime SOAP envelope at the standard
// Device Service path. It returns a fingerprint when the response shape
// indicates an ONVIF responder (either a real GetSystemDateAndTimeResponse
// or a SOAP Fault carrying the ONVIF namespace). Returns nil for anything
// else, so the caller can keep the plain HTTP result.
func (s *Stack) probeONVIF(ctx context.Context, client *http.Client, scheme, addr string) *FingerprintResult {
	url := fmt.Sprintf("%s://%s%s", scheme, addr, onvifDevicePath)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(onvifGetSystemDateAndTimeSOAP))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Content-Type", `application/soap+xml; charset=utf-8; action="`+onvifGetSystemDateAction+`"`)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	defer func() { _ = resp.Body.Close() }()

	limit := int64(s.cfg.MaxBody)
	if limit <= 0 || limit > onvifResponseLimit {
		limit = onvifResponseLimit
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil
	}

	xml := string(body)
	lowered := strings.ToLower(xml)

	hasResponse := strings.Contains(lowered, "getsystemdateandtimeresponse")
	hasFault := strings.Contains(lowered, ":fault") || strings.Contains(lowered, "<fault")
	hasONVIFNamespace := strings.Contains(lowered, "onvif.org/ver10/device/wsdl") ||
		strings.Contains(lowered, "onvif.org/ver10/schema")

	if !hasResponse && (!hasFault || !hasONVIFNamespace) {
		return nil
	}

	notAuthorized := strings.Contains(lowered, "notauthorized")
	authRequired := resp.StatusCode == http.StatusUnauthorized || notAuthorized

	fp := &FingerprintResult{
		Product:      productONVIF,
		AuthRequired: &authRequired,
		Anonymous:    !authRequired && hasResponse,
		RawJSON: mustMarshalJSON(map[string]any{
			"endpoint":      onvifDevicePath,
			"soap_action":   onvifGetSystemDateAction,
			"status_code":   resp.StatusCode,
			"response_body": xml,
		}),
	}

	return fp
}
