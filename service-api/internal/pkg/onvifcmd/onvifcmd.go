// Package onvifcmd builds minimal ONVIF SOAP 1.2 requests for interactive host
// tooling (distinct from passive scan probes).
package onvifcmd

import (
	"encoding/xml"
	"errors"
	"strings"
)

const (
	cmdGetStreamURI   = "get_stream_uri"
	cmdGetSnapshotURI = "get_snapshot_uri"
)

const (
	soapDeviceEnvelopeOpen = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:tds="http://www.onvif.org/ver10/device/wsdl">` +
		`<s:Body>`

	soapMediaEnvelopeOpen = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:trt="http://www.onvif.org/ver10/media/wsdl"` +
		` xmlns:tt="http://www.onvif.org/ver10/schema">` +
		`<s:Body>`

	soapImagingEnvelopeOpen = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:timg="http://www.onvif.org/ver20/imaging/wsdl"` +
		` xmlns:tt="http://www.onvif.org/ver10/schema">` +
		`<s:Body>`

	soapPTZEnvelopeOpen = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"` +
		` xmlns:tt="http://www.onvif.org/ver10/schema">` +
		`<s:Body>`

	soapEnvelopeClose = `</s:Body></s:Envelope>`
)

var deviceSoapBodies = map[string]string{
	"get_system_date_and_time": `<tds:GetSystemDateAndTime/>`,
	"get_capabilities": `<tds:GetCapabilities>` +
		`<tds:Category>All</tds:Category>` +
		`</tds:GetCapabilities>`,
	"get_device_information": `<tds:GetDeviceInformation/>`,
	"get_hostname":           `<tds:GetHostname/>`,
}

var deviceSoapActions = map[string]string{
	"get_system_date_and_time": "http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime",
	"get_capabilities":         "http://www.onvif.org/ver10/device/wsdl/GetCapabilities",
	"get_device_information":   "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
	"get_hostname":             "http://www.onvif.org/ver10/device/wsdl/GetHostname",
}

var mediaSoapActions = map[string]string{
	"get_media_profiles":             "http://www.onvif.org/ver10/media/wsdl/GetProfiles",
	cmdGetStreamURI:                  "http://www.onvif.org/ver10/media/wsdl/GetStreamUri",
	"get_video_sources":              "http://www.onvif.org/ver10/media/wsdl/GetVideoSources",
	cmdGetSnapshotURI:                "http://www.onvif.org/ver10/media/wsdl/GetSnapshotUri",
	"get_media_service_capabilities": "http://www.onvif.org/ver10/media/wsdl/GetServiceCapabilities",
}

var imagingSoapActions = map[string]string{
	"get_imaging_settings": "http://www.onvif.org/ver20/imaging/wsdl/GetImagingSettings",
	"get_imaging_options":  "http://www.onvif.org/ver20/imaging/wsdl/GetOptions",
}

var ptzSoapActions = map[string]string{
	"get_ptz_configurations": "http://www.onvif.org/ver20/ptz/wsdl/GetConfigurations",
	"get_ptz_nodes":          "http://www.onvif.org/ver20/ptz/wsdl/GetNodes",
	"get_ptz_status":         "http://www.onvif.org/ver20/ptz/wsdl/GetStatus",
}

// EnvelopeInput carries tokens required by specific ONVIF command presets.
type EnvelopeInput struct {
	Command          string
	ProfileToken     string
	VideoSourceToken string
}

// IsMediaCommand reports whether command targets the ONVIF Media Service.
func IsMediaCommand(command string) bool {
	switch command {
	case "get_media_profiles", cmdGetStreamURI, "get_video_sources",
		cmdGetSnapshotURI, "get_media_service_capabilities":
		return true
	default:
		return false
	}
}

// IsImagingCommand reports whether command targets the ONVIF Imaging Service.
func IsImagingCommand(command string) bool {
	switch command {
	case "get_imaging_settings", "get_imaging_options":
		return true
	default:
		return false
	}
}

// IsPTZCommand reports whether command targets the ONVIF PTZ Service.
func IsPTZCommand(command string) bool {
	switch command {
	case "get_ptz_configurations", "get_ptz_nodes", "get_ptz_status":
		return true
	default:
		return false
	}
}

// SOAPAction returns the SOAP 1.2 action URI for a known command key, or empty
// if command is unknown.
func SOAPAction(command string) string {
	if a := deviceSoapActions[command]; a != "" {
		return a
	}

	if a := mediaSoapActions[command]; a != "" {
		return a
	}

	if a := imagingSoapActions[command]; a != "" {
		return a
	}

	return ptzSoapActions[command]
}

// BuildEnvelope returns a full SOAP document for the preset in in.
func BuildEnvelope(in EnvelopeInput) (string, error) {
	switch {
	case IsMediaCommand(in.Command):
		return buildMediaEnvelope(in)
	case IsImagingCommand(in.Command):
		return buildImagingEnvelope(in)
	case IsPTZCommand(in.Command):
		return buildPTZEnvelope(in)
	default:
		return buildDeviceEnvelope(in.Command)
	}
}

func buildDeviceEnvelope(command string) (string, error) {
	body, ok := deviceSoapBodies[command]
	if !ok {
		return "", errors.New("unknown onvif command: " + command)
	}

	var b strings.Builder

	b.WriteString(soapDeviceEnvelopeOpen)
	b.WriteString(body)
	b.WriteString(soapEnvelopeClose)

	return b.String(), nil
}

func buildMediaEnvelope(in EnvelopeInput) (string, error) {
	var inner string

	switch in.Command {
	case "get_media_profiles":
		inner = `<trt:GetProfiles/>`
	case "get_video_sources":
		inner = `<trt:GetVideoSources/>`
	case "get_media_service_capabilities":
		inner = `<trt:GetServiceCapabilities/>`
	case cmdGetStreamURI, cmdGetSnapshotURI:
		if in.ProfileToken == "" {
			return "", errors.New("profile token is required for " + in.Command)
		}

		var esc strings.Builder

		if err := xml.EscapeText(&esc, []byte(in.ProfileToken)); err != nil {
			return "", err
		}

		tok := esc.String()

		switch in.Command {
		case cmdGetStreamURI:
			inner = `<trt:GetStreamUri>` +
				`<trt:StreamSetup>` +
				`<tt:Stream>RTP-Unicast</tt:Stream>` +
				`<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>` +
				`</trt:StreamSetup>` +
				`<trt:ProfileToken>` + tok + `</trt:ProfileToken>` +
				`</trt:GetStreamUri>`
		case cmdGetSnapshotURI:
			inner = `<trt:GetSnapshotUri><trt:ProfileToken>` + tok + `</trt:ProfileToken></trt:GetSnapshotUri>`
		}
	default:
		return "", errors.New("unknown onvif media command: " + in.Command)
	}

	var b strings.Builder

	b.WriteString(soapMediaEnvelopeOpen)
	b.WriteString(inner)
	b.WriteString(soapEnvelopeClose)

	return b.String(), nil
}

func buildImagingEnvelope(in EnvelopeInput) (string, error) {
	if in.VideoSourceToken == "" {
		return "", errors.New("video source token is required for imaging commands")
	}

	var esc strings.Builder

	if err := xml.EscapeText(&esc, []byte(in.VideoSourceToken)); err != nil {
		return "", err
	}

	tok := esc.String()

	var inner string

	switch in.Command {
	case "get_imaging_settings":
		inner = `<timg:GetImagingSettings><timg:VideoSourceToken>` + tok + `</timg:VideoSourceToken></timg:GetImagingSettings>`
	case "get_imaging_options":
		inner = `<timg:GetOptions><timg:VideoSourceToken>` + tok + `</timg:VideoSourceToken></timg:GetOptions>`
	default:
		return "", errors.New("unknown onvif imaging command: " + in.Command)
	}

	var b strings.Builder

	b.WriteString(soapImagingEnvelopeOpen)
	b.WriteString(inner)
	b.WriteString(soapEnvelopeClose)

	return b.String(), nil
}

func buildPTZEnvelope(in EnvelopeInput) (string, error) {
	var inner string

	switch in.Command {
	case "get_ptz_configurations":
		inner = `<tptz:GetConfigurations/>`
	case "get_ptz_nodes":
		inner = `<tptz:GetNodes/>`
	case "get_ptz_status":
		if in.ProfileToken == "" {
			return "", errors.New("profile token is required for get_ptz_status")
		}

		var esc strings.Builder

		if err := xml.EscapeText(&esc, []byte(in.ProfileToken)); err != nil {
			return "", err
		}

		inner = `<tptz:GetStatus><tptz:ProfileToken>` + esc.String() + `</tptz:ProfileToken></tptz:GetStatus>`
	default:
		return "", errors.New("unknown onvif ptz command: " + in.Command)
	}

	var b strings.Builder

	b.WriteString(soapPTZEnvelopeOpen)
	b.WriteString(inner)
	b.WriteString(soapEnvelopeClose)

	return b.String(), nil
}

// MaybeInjectWSSE injects a WS-Security UsernameToken header when mode is wsse.
func MaybeInjectWSSE(soap, mode, username, password string) (string, error) {
	if mode != "wsse" {
		return soap, nil
	}

	out, err := injectWSSESecurityHeader(soap, username, password)
	if err != nil {
		return "", err
	}

	return out, nil
}
