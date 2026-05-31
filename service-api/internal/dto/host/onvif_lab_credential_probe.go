package host

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// ONVIFLabCredentialProbeRequest is the JSON body for POST /v1/hosts/{ip}/onvif-lab-credential-probe.
type ONVIFLabCredentialProbeRequest struct {
	Port       uint16 `json:"port" validate:"required,gte=1,lte=65535"`
	Scheme     string `json:"scheme" validate:"required,oneof=http https"`
	Transport  string `json:"transport" validate:"omitempty,oneof=tcp"`
	DevicePath string `json:"device_path" validate:"omitempty,max=512,noctrl"`
	User       string `json:"user" validate:"omitempty,max=256,noctrl"`
}

// ApplyDefaults fills empty optional fields with the canonical defaults. Must
// be called after JSON decoding and before IsValid so the validator sees the
// effective values.
func (r *ONVIFLabCredentialProbeRequest) ApplyDefaults() {
	if r.Transport == "" {
		r.Transport = onvifTransportTCPDefault
	}

	if r.DevicePath == "" {
		r.DevicePath = onvifDevicePathDefault
	}
}

// IsValid validates the lab credential probe request payload.
func (r *ONVIFLabCredentialProbeRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate onvif lab credential probe request: %w", err)
	}

	if r.DevicePath != "" && !strings.HasPrefix(r.DevicePath, "/") {
		return errors.New("device_path must start with /")
	}

	return nil
}
