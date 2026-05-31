package handler

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/rtspsnapshot"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
	rtspsvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/rtsp"
)

const (
	rtspFFmpegTransportTCP = "tcp"
	rtspFFmpegTransportUDP = "udp"
)

// ffmpegRTSPTransportString maps stored service wire transport to ffmpeg -rtsp_transport values.
func ffmpegRTSPTransportString(wire servicerepository.Transport) string {
	if wire == servicerepository.TransportUDP {
		return rtspFFmpegTransportUDP
	}

	return rtspFFmpegTransportTCP
}

// writeRTSPSnapshotCaptureFailure logs and writes HTTP for a failed rtspsnapshot.CaptureJPEG.
// Returns timedOut when capErr is rtspsnapshot.ErrTimeout (for metrics in ONVIF flow).
func writeRTSPSnapshotCaptureFailure(
	w http.ResponseWriter,
	apiLogger *zap.SugaredLogger,
	capErr error,
	logEventPrefix string,
) (timedOut bool) {
	if capErr == nil {
		apiLogger.Warnw(logEventPrefix+" capture failed", zap.String("reason", "nil_error"))

		httperror.WriteInvalidArgument(w, apiLogger, "rtsp_snapshot_failed")

		return false
	}

	if errors.Is(capErr, rtspsnapshot.ErrTimeout) {
		apiLogger.Warnw(logEventPrefix + " timed out")

		httperror.WriteInvalidArgument(w, apiLogger, "rtsp_snapshot_timeout")

		return true
	}

	var capFail *rtspsnapshot.CaptureFailure

	if errors.As(capErr, &capFail) {
		fields := []any{zap.Int("ffmpeg_exit_code", capFail.ExitCode)}

		if capFail.StderrHint != "" {
			fields = append(fields, zap.String("ffmpeg_stderr_hint", capFail.StderrHint))
		}

		apiLogger.Warnw(logEventPrefix+" capture failed", fields...)
	} else {
		apiLogger.Warnw(logEventPrefix+" capture failed", zap.Error(capErr))
	}

	httperror.WriteInvalidArgument(w, apiLogger, "rtsp_snapshot_failed")

	return false
}

// tryCaptureRTSPSnapshotJPEG acquires one rtspGate slot, runs CaptureJPEG, then releases.
// When busy is true, err is always nil. Otherwise err is the capture result.
func tryCaptureRTSPSnapshotJPEG(
	ctx context.Context,
	gate *rtspsvc.SnapshotGate,
	cfg rtspsnapshot.Config,
	source *url.URL,
	ffTransport string,
) (jpeg []byte, busy bool, err error) {
	release, gateBusy := gate.TryAcquire()
	if gateBusy {
		return nil, true, nil
	}

	defer release()

	jpeg, err = rtspsnapshot.CaptureJPEG(ctx, cfg, source, ffTransport)

	return jpeg, false, err
}
