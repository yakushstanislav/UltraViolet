package handler

import (
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"go.uber.org/zap"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/metrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/onvifcmd"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/onvifparse"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/rtspsnapshot"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
)

const (
	onvifRTSnapOutcomeOK          = "ok"
	onvifRTSnapOutcomeHTTPError   = "http_error"
	onvifRTSnapOutcomeDisabled    = "disabled"
	onvifRTSnapOutcomeParseError  = "parse_error"
	onvifRTSnapOutcomeAuthError   = "auth_error"
	onvifRTSnapOutcomeBusy        = "busy"
	onvifRTSnapOutcomeTimeout     = "timeout"
	onvifRTSnapOutcomeRateLimited = "rate_limited"
	onvifRTSPDefaultPort          = uint16(554)
)

func onvifRTSPURIHostEqualsCameraIP(rtspURL *url.URL, camera netip.Addr) bool {
	if rtspURL == nil {
		return false
	}

	h := rtspURL.Hostname()

	ip, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}

	// Align IPv4-mapped IPv6 (::ffff:a.b.c.d) with a plain IPv4 path address.
	return ip.Unmap().Compare(camera.Unmap()) == 0
}

func (h *Router) postHostONVIFRTSPSnapshotHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	outcome := onvifRTSnapOutcomeHTTPError

	defer func() {
		metrics.RecordONVIFRTSPSnapshot(outcome)
	}()

	if !h.services.ONVIF.Config.RTSPSnapshotEnabled {
		outcome = onvifRTSnapOutcomeDisabled

		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFRTSPSnapshotDisabled)

		return
	}

	if h.services.RTSP.SnapshotGate == nil {
		outcome = onvifRTSnapOutcomeDisabled

		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeRTSPSnapshotDisabled)

		return
	}

	if h.services.ONVIF.CommandGate == nil {
		outcome = onvifRTSnapOutcomeDisabled

		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFCommandDisabled)

		return
	}

	if h.services.ONVIF.RateLimiter != nil && !h.services.ONVIF.RateLimiter.Allow() {
		outcome = onvifRTSnapOutcomeRateLimited

		httperror.WriteCode(w, h.logger, http.StatusTooManyRequests, httperror.CodeONVIFRateLimited)

		return
	}

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req hostdto.ONVIFRTSPSnapshotRequest

	if err = h.decodeBody(w, r, &req); err != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		requestLogger.Warnw("Can't decode ONVIF RTSP snapshot body", zap.Error(err))

		h.writeDecodeError(w, err)

		return
	}

	req.ApplyDefaults()

	if err = req.IsValid(); err != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		requestLogger.Warnw("Invalid ONVIF RTSP snapshot request", zap.Error(err))

		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	hostRow, err := h.services.Host.HostByIP(ctx, addr)
	if err != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	ok, err := h.services.Host.HasONVIFEligiblePort(ctx, hostRow.ID, req.ONVIFPort)
	if err != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	if !ok {
		outcome = onvifRTSnapOutcomeHTTPError

		httperror.WriteInvalidArgument(w, h.logger, "onvif_service_not_found_for_host")

		return
	}

	soapBody, err := onvifcmd.BuildEnvelope(onvifcmd.EnvelopeInput{
		Command:      "get_stream_uri",
		ProfileToken: req.ProfileToken,
	})
	if err != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		requestLogger.Warnw("Can't build ONVIF GetStreamUri envelope", zap.Error(err))

		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	soapBody, err = onvifcmd.MaybeInjectWSSE(soapBody, wsseMode(req.AuthMode), req.User, req.Password)
	if err != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		requestLogger.Warnw("Can't build ONVIF WS-Security header", zap.Error(err))

		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	action := onvifcmd.SOAPAction("get_stream_uri")
	if action == "" {
		outcome = onvifRTSnapOutcomeHTTPError

		requestLogger.Warnw("Missing SOAP action for get_stream_uri")

		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	release, busy := h.services.ONVIF.CommandGate.TryAcquire()
	if busy {
		outcome = onvifRTSnapOutcomeBusy

		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFCommandBusy)

		return
	}

	defer release()

	statusCode, bodyStr, _, _, doErr := h.onvifSOAPPost(
		ctx,
		requestLogger,
		addr,
		req.ONVIFPort,
		req.Scheme,
		req.MediaServicePath,
		soapBody,
		action,
		req.AuthMode,
		req.User,
		req.Password,
		0,
	)
	if doErr != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		requestLogger.Warnw("ONVIF GetStreamUri HTTP failed", zap.Error(doErr))

		httperror.WriteInvalidArgument(w, h.logger, "onvif_http_error")

		return
	}

	if statusCode < 200 || statusCode >= 300 {
		if statusCode == http.StatusUnauthorized {
			outcome = onvifRTSnapOutcomeAuthError

			httperror.WriteInvalidArgument(w, h.logger, "onvif_auth_failed")

			return
		}

		outcome = onvifRTSnapOutcomeHTTPError

		requestLogger.Warnw("ONVIF GetStreamUri returned non-success HTTP status", zap.Int("status_code", statusCode))

		httperror.WriteInvalidArgument(w, h.logger, "onvif_http_error")

		return
	}

	pr := onvifparse.Parse("get_stream_uri", bodyStr)

	uriStr, _ := pr.Data["uri"].(string)
	if uriStr == "" {
		outcome = onvifRTSnapOutcomeParseError

		httperror.WriteInvalidArgument(w, h.logger, "onvif_rtsp_stream_uri_missing")

		return
	}

	rtspURL, perr := url.Parse(uriStr)
	if perr != nil || rtspURL == nil || !strings.EqualFold(rtspURL.Scheme, "rtsp") {
		outcome = onvifRTSnapOutcomeParseError

		httperror.WriteInvalidArgument(w, h.logger, "onvif_rtsp_stream_uri_invalid")

		return
	}

	if !onvifRTSPURIHostEqualsCameraIP(rtspURL, addr) {
		outcome = onvifRTSnapOutcomeHTTPError

		httperror.WriteInvalidArgument(w, h.logger, "onvif_rtsp_stream_uri_host_mismatch")

		return
	}

	rtspPort := onvifRTSPDefaultPort

	if p := rtspURL.Port(); p != "" {
		n, convErr := strconv.ParseUint(p, 10, 16)
		if convErr != nil {
			outcome = onvifRTSnapOutcomeParseError

			httperror.WriteInvalidArgument(w, h.logger, "onvif_rtsp_stream_uri_invalid")

			return
		}

		rtspPort = uint16(n)
	}

	wireTransport := servicerepository.TransportTCP

	if req.Transport == "udp" {
		wireTransport = servicerepository.TransportUDP
	}

	ok, err = h.services.Host.HasRTSPOnPort(ctx, hostRow.ID, rtspPort, wireTransport)
	if err != nil {
		outcome = onvifRTSnapOutcomeHTTPError

		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	if !ok {
		outcome = onvifRTSnapOutcomeHTTPError

		httperror.WriteInvalidArgument(w, h.logger, "rtsp_service_not_found_for_host")

		return
	}

	ffTransport := ffmpegRTSPTransportString(wireTransport)

	jpeg, rtspGateBusy, capErr := tryCaptureRTSPSnapshotJPEG(ctx, h.services.RTSP.SnapshotGate, rtspsnapshot.Config{
		FFmpegPath:  h.services.RTSP.Config.FFmpegPath,
		ExecTimeout: h.services.RTSP.Config.ExecTimeout,
	}, rtspURL, ffTransport)

	if rtspGateBusy {
		outcome = onvifRTSnapOutcomeBusy

		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeRTSPSnapshotBusy)

		return
	}

	if capErr != nil {
		if writeRTSPSnapshotCaptureFailure(w, h.logger, capErr, "ONVIF RTSP snapshot") {
			outcome = onvifRTSnapOutcomeTimeout
		} else {
			outcome = onvifRTSnapOutcomeHTTPError
		}

		return
	}

	outcome = onvifRTSnapOutcomeOK

	w.Header().Set("Content-Type", "image/jpeg")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(jpeg); err != nil && h.logger != nil {
		h.logger.Warnw("Can't write ONVIF RTSP snapshot body", zap.Error(err))
	}
}
