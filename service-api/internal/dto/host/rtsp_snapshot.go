package host

import (
	"errors"
	"fmt"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/validate"
)

// RTSPSnapshotRequest is the JSON body for POST /v1/hosts/{ip}/rtsp-snapshot.
type RTSPSnapshotRequest struct {
	Port               uint16 `json:"port" validate:"required,gte=1,lte=65535"`
	Path               string `json:"path" validate:"max=512,noctrl"`
	Transport          string `json:"transport" validate:"omitempty,oneof=tcp udp"`
	User               string `json:"user" validate:"omitempty,max=256,noctrl"`
	Password           string `json:"password" validate:"omitempty,max=256,noctrl"`
	AutoTryCommonPaths bool   `json:"auto_try_common_paths"`
}

// IsValid validates the RTSP snapshot request payload.
func (r RTSPSnapshotRequest) IsValid() error {
	if err := validate.Struct(r); err != nil {
		return fmt.Errorf("can't validate rtsp snapshot request: %w", err)
	}

	if !r.AutoTryCommonPaths && r.Path == "" {
		return errors.New("path is required unless auto_try_common_paths is true")
	}

	return nil
}
