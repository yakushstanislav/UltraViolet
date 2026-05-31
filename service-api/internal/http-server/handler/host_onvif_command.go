package handler

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/icholy/digest"
	"go.uber.org/zap"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"
	auditmw "github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/audit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/metrics"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/onvifcmd"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/onvifparse"
	onvifsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/onvif"
)

const (
	onvifResponseBodyMax = 256 * 1024
	onvifHTTPMaxAttempts = 3
	onvifRetryBackoff    = 200 * time.Millisecond
	onvifWireTCP         = "tcp"
)

const (
	onvifAuthModeBasic = "basic"

	onvifCmdOutcomeHTTPError  = "http_error"
	onvifCmdOutcomeOK         = "ok"
	onvifCmdOutcomeAuthError  = "auth_error"
	onvifCmdOutcomeParseError = "parse_error"
)

func wsseMode(authMode string) string {
	if authMode == "wsse" {
		return "wsse"
	}

	return ""
}

// onvifParseFailureElevatesMetric selects commands where empty parsed data with
// warnings counts as a hard parse failure for metrics (missing stream URI, etc.).
func onvifParseFailureElevatesMetric(command string) bool {
	switch command {
	case "get_stream_uri", "get_snapshot_uri":
		return true
	default:
		return false
	}
}

// onvifTransportErr reports whether err is a transport-level failure worth
// retrying once or twice (many cameras reset the first TCP/TLS hop or misbehave
// when the client offers HTTP/2 via ALPN).
func onvifTransportErr(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	var ue *url.Error
	if errors.As(err, &ue) {
		return onvifTransportErr(ue.Err)
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return onvifTransportErr(opErr.Err)
	}

	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "tls handshake") ||
		strings.Contains(msg, "unexpected eof") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "eof")
}

// onvifHTTPRoundTripper builds the RoundTripper used for every ONVIF SOAP call.
//
// We use a lenient HTTP/1.1 transport (see onvifLenientTransport) instead of
// the stdlib http.Transport because cheap IP cameras frequently emit response
// headers that the standard parser rejects — most often a Digest challenge
// preceded by a bare "Www-Authenticate" line without a colon. Wrapping the
// lenient transport with icholy/digest keeps Digest auth working unchanged.
func onvifHTTPRoundTripper(authMode, user, pass string) http.RoundTripper {
	base := newONVIFLenientTransport()

	if authMode == "digest" {
		return &digest.Transport{
			Username:  user,
			Password:  pass,
			Transport: base,
		}
	}

	return base
}

func (h *Router) postHostONVIFCommandHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	if h.services.ONVIF.CommandGate == nil {
		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFCommandDisabled)

		return
	}

	if h.services.ONVIF.RateLimiter != nil && !h.services.ONVIF.RateLimiter.Allow() {
		httperror.WriteCode(w, h.logger, http.StatusTooManyRequests, httperror.CodeONVIFRateLimited)

		return
	}

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req hostdto.ONVIFCommandRequest

	if err = h.decodeBody(w, r, &req); err != nil {
		requestLogger.Warnw("Can't decode ONVIF command body", zap.Error(err))
		h.writeDecodeError(w, err)

		return
	}

	req.ApplyDefaults()

	if err = req.IsValid(); err != nil {
		requestLogger.Warnw("Invalid ONVIF command request", zap.Error(err))
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	if hint := auditmw.HintFor(r); hint != nil {
		hint.Set("onvif:" + addr.String() + ":" + strconv.FormatUint(uint64(req.Port), 10) + ":" + req.Command)
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

	wantParse := req.Parse || req.ResponseShape == "json"

	if h.serveONVIFCacheHit(w, hostRow.ID, req, wantParse) {
		return
	}

	soapBody, action, ok := h.buildONVIFSOAP(w, requestLogger, req)
	if !ok {
		return
	}

	release, busy := h.services.ONVIF.CommandGate.TryAcquire()
	if busy {
		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeONVIFCommandBusy)

		return
	}

	defer release()

	onvifOutcome := onvifCmdOutcomeHTTPError

	defer func() {
		metrics.RecordONVIFCommand(req.Command, onvifOutcome)
	}()

	statusCode, bodyStr, ct, truncated, doErr := h.onvifSOAPPost(ctx, requestLogger, addr, req.Port, req.Scheme, onvifServicePath(req), soapBody, action, req.AuthMode, req.User, req.Password, 0)
	if doErr != nil {
		requestLogger.Warnw("ONVIF HTTP request failed after attempts",
			zap.Error(doErr),
			zap.Uint16("port", req.Port),
		)

		httperror.WriteInvalidArgument(w, h.logger, "onvif_http_error")

		return
	}

	payload := map[string]any{
		"status_code":  statusCode,
		"content_type": ct,
		"body":         bodyStr,
		"truncated":    truncated,
	}

	onvifOutcome = onvifOutcomeForStatus(statusCode)

	if wantParse && statusCode >= 200 && statusCode < 300 {
		pr := onvifparse.Parse(req.Command, bodyStr)
		if len(pr.Data) > 0 {
			payload["parsed"] = pr.Data
		}

		if len(pr.Warnings) > 0 {
			payload["parse_warnings"] = pr.Warnings
		}

		if onvifOutcome == onvifCmdOutcomeOK && len(pr.Data) == 0 && len(pr.Warnings) > 0 &&
			onvifParseFailureElevatesMetric(req.Command) {
			onvifOutcome = onvifCmdOutcomeParseError
		}
	}

	if h.services.ONVIF.ResponseCache != nil && onvifsvc.CommandCacheable(req) && statusCode >= 200 && statusCode < 300 && !truncated {
		h.services.ONVIF.ResponseCache.Set(onvifsvc.CacheKey(hostRow.ID, req), onvifsvc.CachedEnvelope{
			StatusCode:  statusCode,
			ContentType: ct,
			Body:        bodyStr,
			Truncated:   truncated,
		})
	}

	h.sendJSONResponse(w, http.StatusOK, payload)
}

// serveONVIFCacheHit looks up the response cache for the request and writes
// the cached envelope back to the client if a hit is found. Returns true when
// the response was served and the handler must stop further processing.
func (h *Router) serveONVIFCacheHit(w http.ResponseWriter, hostID uint64, req hostdto.ONVIFCommandRequest, wantParse bool) bool {
	if h.services.ONVIF.ResponseCache == nil || !onvifsvc.CommandCacheable(req) {
		return false
	}

	cached, hit := h.services.ONVIF.ResponseCache.Get(onvifsvc.CacheKey(hostID, req))
	if !hit {
		return false
	}

	payload := map[string]any{
		"status_code":  cached.StatusCode,
		"content_type": cached.ContentType,
		"body":         cached.Body,
		"truncated":    cached.Truncated,
	}

	if wantParse && cached.StatusCode >= 200 && cached.StatusCode < 300 {
		pr := onvifparse.Parse(req.Command, cached.Body)
		if len(pr.Data) > 0 {
			payload["parsed"] = pr.Data
		}

		if len(pr.Warnings) > 0 {
			payload["parse_warnings"] = pr.Warnings
		}

		if len(pr.Data) == 0 && len(pr.Warnings) > 0 && onvifParseFailureElevatesMetric(req.Command) {
			metrics.RecordONVIFCommand(req.Command, onvifCmdOutcomeParseError)
			h.sendJSONResponse(w, http.StatusOK, payload)

			return true
		}
	}

	metrics.RecordONVIFCommand(req.Command, "cache_hit")
	h.sendJSONResponse(w, http.StatusOK, payload)

	return true
}

// buildONVIFSOAP assembles the SOAP envelope and SOAPAction header for the
// request. On failure it writes an HTTP error response and returns ok=false.
func (h *Router) buildONVIFSOAP(w http.ResponseWriter, requestLogger *zap.SugaredLogger, req hostdto.ONVIFCommandRequest) (soapBody, action string, ok bool) {
	body, err := onvifcmd.BuildEnvelope(onvifcmd.EnvelopeInput{
		Command:          req.Command,
		ProfileToken:     req.ProfileToken,
		VideoSourceToken: req.VideoSourceToken,
	})
	if err != nil {
		requestLogger.Warnw("Unknown ONVIF command preset", zap.Error(err))
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return "", "", false
	}

	body, err = onvifcmd.MaybeInjectWSSE(body, wsseMode(req.AuthMode), req.User, req.Password)
	if err != nil {
		requestLogger.Warnw("Can't build ONVIF WS-Security header", zap.Error(err))
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return "", "", false
	}

	soapAction := onvifcmd.SOAPAction(req.Command)
	if soapAction == "" {
		requestLogger.Warnw("Missing SOAP action for ONVIF command", zap.String("command", req.Command))
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return "", "", false
	}

	return body, soapAction, true
}

// onvifServicePath returns the SOAP endpoint path for the given command,
// picking media/imaging/PTZ service paths over the default device path.
func onvifServicePath(req hostdto.ONVIFCommandRequest) string {
	switch {
	case onvifcmd.IsMediaCommand(req.Command):
		return req.MediaServicePath
	case onvifcmd.IsImagingCommand(req.Command):
		return req.ImagingServicePath
	case onvifcmd.IsPTZCommand(req.Command):
		return req.PTZServicePath
	default:
		return req.DevicePath
	}
}

// onvifOutcomeForStatus maps an HTTP status code to a metrics outcome label.
func onvifOutcomeForStatus(statusCode int) string {
	switch {
	case statusCode == http.StatusUnauthorized:
		return onvifCmdOutcomeAuthError
	case statusCode >= 200 && statusCode < 300:
		return onvifCmdOutcomeOK
	default:
		return onvifCmdOutcomeHTTPError
	}
}

// onvifSOAPPost issues a single ONVIF SOAP POST with transport retries and returns
// the HTTP status, UTF-8 body (possibly truncated), Content-Type, and truncation flag.
func (h *Router) onvifSOAPPost(
	ctx context.Context,
	requestLogger *zap.SugaredLogger,
	addr netip.Addr,
	port uint16,
	scheme, httpPath, soapBody, action, authMode, user, password string,
	perAttemptTimeout time.Duration,
) (
	statusCode int,
	body string,
	contentType string,
	truncated bool,
	doErr error,
) {
	u := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(addr.String(), strconv.FormatUint(uint64(port), 10)),
		Path:   httpPath,
	}

	targetURL := u.String()

	baseTimeout := h.services.ONVIF.Config.RequestTimeout
	if perAttemptTimeout > 0 {
		baseTimeout = perAttemptTimeout
	}

	// Total budget across all retries — capped by the parent ctx so a worst-
	// case 3 × baseTimeout + 2 × backoff can't tie up the gate longer than
	// the caller expected. Each attempt gets the smaller of baseTimeout and
	// the remaining budget.
	totalBudget := time.Duration(onvifHTTPMaxAttempts)*baseTimeout +
		time.Duration(onvifHTTPMaxAttempts-1)*onvifRetryBackoff

	attemptDeadline := time.Now().Add(totalBudget)

	var resp *http.Response

attemptLoop:
	for attempt := 1; attempt <= onvifHTTPMaxAttempts; attempt++ {
		remaining := time.Until(attemptDeadline)
		if remaining <= 0 {
			doErr = errors.New("onvif http request exceeded total budget")

			break attemptLoop
		}

		timeout := baseTimeout
		if remaining < timeout {
			timeout = remaining
		}

		client := &http.Client{
			Timeout:   timeout,
			Transport: onvifHTTPRoundTripper(authMode, user, password),
		}

		if attempt > 1 {
			select {
			case <-ctx.Done():
				doErr = ctx.Err()

				break attemptLoop
			case <-time.After(onvifRetryBackoff):
			}

			requestLogger.Infow("Retrying ONVIF HTTP request",
				zap.Int("attempt", attempt),
				zap.Uint16("port", port),
			)
		}

		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(soapBody))
		if reqErr != nil {
			requestLogger.Warnw("Can't build ONVIF HTTP request", zap.Error(reqErr))
			doErr = reqErr

			return 0, "", "", false, doErr
		}

		httpReq.Header.Set("User-Agent", "UltraViolet/0.1")
		httpReq.Header.Set("Content-Type", `application/soap+xml; charset=utf-8; action="`+action+`"`)

		if authMode == onvifAuthModeBasic && (user != "" || password != "") {
			httpReq.SetBasicAuth(user, password)
		}

		resp, doErr = client.Do(httpReq)
		if doErr == nil {
			break attemptLoop
		}

		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}

		resp = nil

		if errors.Is(doErr, context.Canceled) {
			break attemptLoop
		}

		requestLogger.Warnw("ONVIF HTTP request attempt failed",
			zap.Error(doErr),
			zap.Int("attempt", attempt),
			zap.Uint16("port", port),
		)

		if attempt == onvifHTTPMaxAttempts || !onvifTransportErr(doErr) {
			break attemptLoop
		}
	}

	if doErr != nil {
		return 0, "", "", false, doErr
	}

	if resp == nil {
		return 0, "", "", false, errors.New("onvif http response nil")
	}

	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, onvifResponseBodyMax+1))
	if err != nil {
		return 0, "", "", false, err
	}

	truncated = len(raw) > onvifResponseBodyMax
	if truncated {
		raw = raw[:onvifResponseBodyMax]
	}

	body = strings.ToValidUTF8(string(raw), "\uFFFD")
	contentType = resp.Header.Get("Content-Type")
	statusCode = resp.StatusCode

	return statusCode, body, contentType, truncated, nil
}
