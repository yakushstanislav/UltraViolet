package handler

import (
	"net/http"
	"net/netip"
	"time"

	"go.uber.org/zap"

	hostdto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/host"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/rtspsnapshot"
	servicerepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/service"
)

func (h *Router) postHostRTSPSnapshotHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	if h.services.RTSP.SnapshotGate == nil {
		h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeRTSPSnapshotDisabled)

		return
	}

	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	var req hostdto.RTSPSnapshotRequest

	if err = h.decodeBody(w, r, &req); err != nil {
		requestLogger.Warnw("Can't decode RTSP snapshot body", zap.Error(err))
		h.writeDecodeError(w, err)

		return
	}

	if err = req.IsValid(); err != nil {
		requestLogger.Warnw("Invalid RTSP snapshot request", zap.Error(err))
		httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

		return
	}

	hostRow, err := h.services.Host.HostByIP(ctx, addr)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	wireTransport := servicerepository.TransportTCP

	if req.Transport == "udp" {
		wireTransport = servicerepository.TransportUDP
	}

	ok, err := h.services.Host.HasRTSPOnPort(ctx, hostRow.ID, req.Port, wireTransport)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	if !ok {
		httperror.WriteInvalidArgument(w, h.logger, "rtsp_service_not_found_for_host")

		return
	}

	paths := rtspsnapshot.SnapshotPaths(req.Path, req.AutoTryCommonPaths)

	multiPath := req.AutoTryCommonPaths && len(paths) > 1

	ffTransport := ffmpegRTSPTransportString(wireTransport)

	var (
		jpeg     []byte
		lastErr  error
		usedPath string
	)

	for i, tryPath := range paths {
		if i > 0 && multiPath {
			select {
			case <-ctx.Done():
				return
			case <-time.After(rtspsnapshot.AutoBetweenPathAttempts):
			}
		}

		u, buildErr := rtspsnapshot.BuildURL(addr, req.Port, tryPath, req.User, req.Password)
		if buildErr != nil {
			httperror.WriteInvalidArgument(w, h.logger, httperror.CodeInvalidArgument)

			return
		}

		if multiPath && ffTransport == rtspFFmpegTransportTCP {
			if rtspsnapshot.PreflightDESCRIBE(ctx, u) == rtspsnapshot.DescribeSkipCapture {
				continue
			}
		}

		execTimeout := h.services.RTSP.Config.ExecTimeout

		if multiPath {
			execTimeout = rtspsnapshot.AutoPathExecTimeout(h.services.RTSP.Config.ExecTimeout)
		}

		tryJPEG, gateBusy, capErr := tryCaptureRTSPSnapshotJPEG(ctx, h.services.RTSP.SnapshotGate, rtspsnapshot.Config{
			FFmpegPath:  h.services.RTSP.Config.FFmpegPath,
			ExecTimeout: execTimeout,
		}, u, ffTransport)

		if gateBusy {
			h.sendResponse(w, http.StatusServiceUnavailable, httperror.CodeRTSPSnapshotBusy)

			return
		}

		if capErr == nil {
			jpeg = tryJPEG
			usedPath = tryPath

			break
		}

		lastErr = capErr
	}

	if jpeg == nil {
		if multiPath {
			requestLogger.Warnw("RTSP snapshot auto paths exhausted", zap.Int("paths_tried", len(paths)))

			httperror.WriteInvalidArgument(w, h.logger, "rtsp_snapshot_paths_exhausted")

			return
		}

		writeRTSPSnapshotCaptureFailure(w, h.logger, lastErr, "RTSP snapshot")

		return
	}

	w.Header().Set("Content-Type", "image/jpeg")

	if multiPath && usedPath != "" {
		w.Header().Set("X-UV-RTSP-Snapshot-Path", usedPath)
	}

	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(jpeg); err != nil && h.logger != nil {
		h.logger.Warnw("Can't write RTSP snapshot body", zap.Error(err))
	}
}
