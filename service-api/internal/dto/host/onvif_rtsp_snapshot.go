package host

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// ONVIFRTSPSnapshotRequest is the JSON body for POST /v1/hosts/{ip}/onvif-rtsp-snapshot.
type ONVIFRTSPSnapshotRequest struct {
	ONVIFPort        uint16 `json:"onvif_port" validate:"required,gte=1,lte=65535"`
	Scheme           string `json:"scheme" validate:"required,oneof=http https"`
	MediaServicePath string `json:"media_service_path" validate:"omitempty,max=512,noctrl"`
	ProfileToken     string `json:"profile_token" validate:"required,noctrl"`
	Transport        string `json:"transport" validate:"omitempty,oneof=tcp udp"`
	AuthMode         string `json:"auth_mode" validate:"omitempty,oneof=none basic digest wsse"`
	User             string `json:"user" validate:"omitempty,max=256,noctrl"`
	Password         string `json:"password" validate:"omitempty,max=256,noctrl"`
}

// ApplyDefaults fills empty optional fields with the canonical defaults. Must
// be called after JSON decoding and before IsValid so the validator sees the
// effective values.
func (r *ONVIFRTSPSnapshotRequest) ApplyDefaults() {
	if r.AuthMode == "" {
		r.AuthMode = onvifAuthModeBasicDefault
	}

	if r.MediaServicePath == "" {
		r.MediaServicePath = onvifMediaServicePathDefault
	}
}

// IsValid validates the ONVIF RTSP snapshot request payload.
func (r *ONVIFRTSPSnapshotRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate onvif rtsp snapshot request: %w", err)
	}

	if !onvifProfileTokenRE.MatchString(r.ProfileToken) {
		return errors.New("profile_token must be 1–128 characters from [A-Za-z0-9_.-]")
	}

	if r.MediaServicePath != "" && !strings.HasPrefix(r.MediaServicePath, "/") {
		return errors.New("media_service_path must start with /")
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

	return nil
}
