package handler

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"
	auditmw "github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/audit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/onvifcmd"
)

// onvifLabProbeCommand is the SOAP preset used by the lab credential probe.
//
// We intentionally avoid GetSystemDateAndTime here: per the ONVIF Core
// Specification it is a PRE_AUTH operation, so the device answers 200 OK
// regardless of credentials — the probe would falsely "match" on any
// password and the real failure surfaces only later on auth-required calls
// like GetProfiles or GetStreamUri. GetDeviceInformation is part of the
// default READ_SYSTEM access policy on every spec-compliant device, returns
// a small body, and lives on the same device service path.
const onvifLabProbeCommand = "get_device_information"

func (h *Router) postHostONVIFLabCredentialProbeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	if !h.services.ONVIF.Config.LabCredentialProbeEnabled {
		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFLabProbeDisabled)

		return
	}

	if h.services.ONVIF.CommandGate == nil {
		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFCommandDisabled)

		return
	}

	if h.services.ONVIF.RateLimiter != nil && !h.services.ONVIF.RateLimiter.Allow() {
		httperror.WriteCode(w, h.logger, http.StatusTooManyRequests, httperror.CodeONVIFRateLimited)

		return
	}

	if len(h.services.ONVIF.LabCredentials) == 0 {
		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFLabProbeNoCredentials)

		return
	}

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req hostdto.ONVIFLabCredentialProbeRequest

	if err = h.decodeBody(w, r, &req); err != nil {
		requestLogger.Warnw("Can't decode ONVIF lab credential probe body", zap.Error(err))
		h.writeDecodeError(w, err)

		return
	}

	req.ApplyDefaults()

	if err = req.IsValid(); err != nil {
		requestLogger.Warnw("Invalid ONVIF lab credential probe request", zap.Error(err))
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	if hint := auditmw.HintFor(r); hint != nil {
		hint.Set("onvif_lab_probe:" + addr.String() + ":" + strconv.FormatUint(uint64(req.Port), 10))
	}

	hostRow, err := h.services.Host.HostByIP(ctx, addr)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	ok, err := h.services.Host.HasONVIFEligiblePort(ctx, hostRow.ID, req.Port)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	if !ok {
		httperror.WriteInvalidArgument(w, h.logger, "onvif_service_not_found_for_host")

		return
	}

	soapBody, err := onvifcmd.BuildEnvelope(onvifcmd.EnvelopeInput{Command: onvifLabProbeCommand})
	if err != nil {
		requestLogger.Warnw("Can't build ONVIF lab probe envelope", zap.Error(err))
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	soapBody, err = onvifcmd.MaybeInjectWSSE(soapBody, "", "", "")
	if err != nil {
		requestLogger.Warnw("Can't finalize ONVIF lab probe envelope", zap.Error(err))
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	action := onvifcmd.SOAPAction(onvifLabProbeCommand)
	if action == "" {
		requestLogger.Warnw("Missing SOAP action for ONVIF lab probe")
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	release, busy := h.services.ONVIF.CommandGate.TryAcquire()
	if busy {
		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFCommandBusy)

		return
	}

	defer release()

	authMode := onvifAuthModeBasic
	httpPath := req.DevicePath
	attempts := 0

	for i, row := range h.services.ONVIF.LabCredentials {
		user := row.User
		if req.User != "" {
			user = req.User
		}

		pass := row.Password

		attempts++

		statusCode, bodyStr, _, _, doErr := h.onvifSOAPPost(
			ctx, requestLogger, addr, req.Port, req.Scheme, httpPath, soapBody, action, authMode, user, pass,
			h.services.ONVIF.Config.LabProbePerAttemptTimeout,
		)
		if doErr != nil {
			requestLogger.Warnw("ONVIF lab probe HTTP request failed",
				zap.Error(doErr),
				zap.Uint16("port", req.Port),
				zap.Int("attempt_index", i),
			)

			httperror.WriteInvalidArgument(w, h.logger, "onvif_http_error")

			return
		}

		if statusCode >= 200 && statusCode < 300 && !onvifResponseIsAuthFault(bodyStr) {
			h.sendJSONResponse(w, http.StatusOK, map[string]any{
				"matched":   true,
				"username":  user,
				"password":  pass,
				"attempts":  attempts,
				"http_code": statusCode,
			})

			return
		}

		if i+1 < len(h.services.ONVIF.LabCredentials) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(h.services.ONVIF.Config.LabProbeInterAttemptDelay):
			}
		}
	}

	h.sendJSONResponse(w, http.StatusOK, map[string]any{
		"matched":  false,
		"attempts": attempts,
	})
}

// onvifResponseIsAuthFault returns true when the SOAP body looks like an
// authorization-related SOAP 1.2 Fault. Some cameras return HTTP 200 even on
// auth failure, encoding the rejection inside the Body — without this check
// the lab probe would treat those responses as a credential match.
func onvifResponseIsAuthFault(body string) bool {
	if body == "" {
		return false
	}

	low := strings.ToLower(body)

	if !strings.Contains(low, "fault") {
		return false
	}

	switch {
	case strings.Contains(low, "notauthorized"),
		strings.Contains(low, "not authorized"),
		strings.Contains(low, "sender not authorized"),
		strings.Contains(low, "authentication failed"),
		strings.Contains(low, "unauthorized"),
		strings.Contains(low, "ter:notauthorized"):
		return true
	}

	return false
}
