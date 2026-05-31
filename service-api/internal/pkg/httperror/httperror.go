// Package httperror exposes the canonical wire-error vocabulary used by all
// HTTP responses, together with a low-level JSON writer.
//
// Domain → HTTP classification lives in the handler package where all
// sentinel-error sources are already imported.
package httperror

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// Canonical wire error codes returned to clients in the JSON body.
const (
	CodeNotFound                   = "not_found"
	CodeMethodNotAllowed           = "method_not_allowed"
	CodeParseURL                   = "parse_url_failed"
	CodeParseBody                  = "parse_body_failed"
	CodeRequestTooLarge            = "request_too_large"
	CodeInvalidArgument            = "invalid_argument"
	CodeInternal                   = "internal_error"
	CodeForbidden                  = "forbidden"
	CodeUnauthorized               = "unauthorized"
	CodeConflict                   = "conflict"
	CodeDemoModeRestricted         = "demo_mode_restricted"
	CodeRTSPSnapshotDisabled       = "rtsp_snapshot_disabled"
	CodeRTSPSnapshotBusy           = "rtsp_snapshot_busy"
	CodeONVIFCommandDisabled       = "onvif_command_disabled"
	CodeONVIFCommandBusy           = "onvif_command_busy"
	CodeONVIFRateLimited           = "onvif_rate_limited"
	CodeONVIFRTSPSnapshotDisabled  = "onvif_rtsp_snapshot_disabled"
	CodeONVIFLabProbeDisabled      = "onvif_lab_probe_disabled"
	CodeONVIFLabProbeNoCredentials = "onvif_lab_probe_no_credentials"
)

type errorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
}

// WriteCode serializes a wire-error code at the given HTTP status.
// log may be nil.
func WriteCode(w http.ResponseWriter, log *zap.SugaredLogger, status int, code string) {
	payload, err := json.Marshal(errorResponse{Error: code})
	if err != nil {
		if log != nil {
			log.Errorw("Can't marshal error response", zap.Error(err))
		}

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(payload); err != nil && log != nil {
		log.Errorw("Can't write error response", zap.Error(err))
	}
}

// WriteInvalidArgument writes HTTP 400 with error=invalid_argument and an
// optional stable machine-readable reason for client-side localization.
func WriteInvalidArgument(w http.ResponseWriter, log *zap.SugaredLogger, reason string) {
	if reason == "" {
		WriteCode(w, log, http.StatusBadRequest, CodeInvalidArgument)

		return
	}

	writeWithReason(w, log, http.StatusBadRequest, CodeInvalidArgument, reason)
}

// WriteConflict writes HTTP 409 with error=conflict and a stable machine-readable
// reason for client-side localization.
func WriteConflict(w http.ResponseWriter, log *zap.SugaredLogger, reason string) {
	writeWithReason(w, log, http.StatusConflict, CodeConflict, reason)
}

func writeWithReason(w http.ResponseWriter, log *zap.SugaredLogger, status int, code, reason string) {
	payload, err := json.Marshal(errorResponse{
		Error:  code,
		Reason: reason,
	})
	if err != nil {
		if log != nil {
			log.Errorw("Can't marshal error response", zap.Error(err))
		}

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(payload); err != nil && log != nil {
		log.Errorw("Can't write error response", zap.Error(err))
	}
}
