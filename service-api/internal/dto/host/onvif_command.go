package host

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/onvifcmd"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

const (
	onvifAuthModeBasicDefault    = "basic"
	onvifTransportTCPDefault     = "tcp"
	onvifDevicePathDefault       = "/onvif/device_service"
	onvifMediaServicePathDefault = "/onvif/media_service"
	onvifImagingPathDefault      = "/onvif/imaging_service"
	onvifPTZPathDefault          = "/onvif/ptz_service"
)

// ApplyDefaults fills empty optional fields with the canonical ONVIF defaults
// (auth mode, transport, service paths). Must be called after JSON decoding
// and before IsValid so the validator sees the effective values.
func (r *ONVIFCommandRequest) ApplyDefaults() {
	if r.AuthMode == "" {
		r.AuthMode = onvifAuthModeBasicDefault
	}

	if r.Transport == "" {
		r.Transport = onvifTransportTCPDefault
	}

	switch {
	case onvifcmd.IsMediaCommand(r.Command):
		if r.MediaServicePath == "" {
			r.MediaServicePath = onvifMediaServicePathDefault
		}
	case onvifcmd.IsImagingCommand(r.Command):
		if r.ImagingServicePath == "" {
			r.ImagingServicePath = onvifImagingPathDefault
		}
	case onvifcmd.IsPTZCommand(r.Command):
		if r.PTZServicePath == "" {
			r.PTZServicePath = onvifPTZPathDefault
		}
	default:
		if r.DevicePath == "" {
			r.DevicePath = onvifDevicePathDefault
		}
	}
}

var onvifProfileTokenRE = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,128}$`)

// ONVIFCommandRequest is the JSON body for POST /v1/hosts/{ip}/onvif-command.
type ONVIFCommandRequest struct {
	Port               uint16 `json:"port" validate:"required,gte=1,lte=65535"`
	Scheme             string `json:"scheme" validate:"required,oneof=http https"`
	Transport          string `json:"transport" validate:"omitempty,oneof=tcp"`
	DevicePath         string `json:"device_path" validate:"omitempty,max=512,noctrl"`
	MediaServicePath   string `json:"media_service_path" validate:"omitempty,max=512,noctrl"`
	ImagingServicePath string `json:"imaging_service_path" validate:"omitempty,max=512,noctrl"`
	PTZServicePath     string `json:"ptz_service_path" validate:"omitempty,max=512,noctrl"`
	Command            string `json:"command" validate:"required,oneof=get_system_date_and_time get_capabilities get_device_information get_hostname get_media_profiles get_stream_uri get_video_sources get_snapshot_uri get_media_service_capabilities get_imaging_settings get_imaging_options get_ptz_configurations get_ptz_nodes get_ptz_status"`
	ProfileToken       string `json:"profile_token" validate:"omitempty,max=128,noctrl"`
	VideoSourceToken   string `json:"video_source_token" validate:"omitempty,max=128,noctrl"`
	AuthMode           string `json:"auth_mode" validate:"omitempty,oneof=none basic digest wsse"`
	Parse              bool   `json:"parse"`
	ResponseShape      string `json:"response_shape" validate:"omitempty,oneof=raw json"`
	User               string `json:"user" validate:"omitempty,max=256,noctrl"`
	Password           string `json:"password" validate:"omitempty,max=256,noctrl"`
}

// IsValid validates the ONVIF command request payload.
func (r *ONVIFCommandRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate onvif command request: %w", err)
	}

	switch r.Command {
	case "get_stream_uri", "get_snapshot_uri":
		if r.ProfileToken == "" {
			return fmt.Errorf("profile_token is required for %s", r.Command)
		}

		if !onvifProfileTokenRE.MatchString(r.ProfileToken) {
			return errors.New("profile_token must be 1–128 characters from [A-Za-z0-9_.-]")
		}
	case "get_ptz_status":
		if r.ProfileToken == "" {
			return errors.New("profile_token is required for get_ptz_status")
		}

		if !onvifProfileTokenRE.MatchString(r.ProfileToken) {
			return errors.New("profile_token must be 1–128 characters from [A-Za-z0-9_.-]")
		}
	case "get_imaging_settings", "get_imaging_options":
		if r.VideoSourceToken == "" {
			return fmt.Errorf("video_source_token is required for %s", r.Command)
		}

		if !onvifProfileTokenRE.MatchString(r.VideoSourceToken) {
			return errors.New("video_source_token must be 1–128 characters from [A-Za-z0-9_.-]")
		}
	}

	if r.ProfileToken != "" {
		switch r.Command {
		case "get_stream_uri", "get_snapshot_uri", "get_ptz_status":
			// allowed
		default:
			return errors.New("profile_token must be empty for this command")
		}
	}

	if r.VideoSourceToken != "" {
		switch r.Command {
		case "get_imaging_settings", "get_imaging_options":
			// allowed
		default:
			return errors.New("video_source_token must be empty for this command")
		}
	}

	switch r.AuthMode {
	case "", "none", "basic":
		// no extra rules
	case "digest":
		if r.User == "" {
			return errors.New("user is required when auth_mode is digest")
		}
	case "wsse":
		if r.User == "" || r.Password == "" {
			return errors.New("user and password are required when auth_mode is wsse")
		}
	}

	if r.DevicePath != "" && !strings.HasPrefix(r.DevicePath, "/") {
		return errors.New("device_path must start with /")
	}

	if r.MediaServicePath != "" && !strings.HasPrefix(r.MediaServicePath, "/") {
		return errors.New("media_service_path must start with /")
	}

	if r.ImagingServicePath != "" && !strings.HasPrefix(r.ImagingServicePath, "/") {
		return errors.New("imaging_service_path must start with /")
	}

	if r.PTZServicePath != "" && !strings.HasPrefix(r.PTZServicePath, "/") {
		return errors.New("ptz_service_path must start with /")
	}

	return nil
}
