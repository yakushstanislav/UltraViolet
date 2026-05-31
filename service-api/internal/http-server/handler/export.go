package handler

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	deltarepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/feature/delta"
)

var deltaCSVHeader = []string{
	"id", "scan_id", "host_id", "service_id", "previous_scan_id",
	"change_type", "details", "created_at",
}

func (h *Router) exportDeltaCSVHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	scanID, err := parseUint64FromPath(r, "id")
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="scan-delta.csv"`)
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	writer := csv.NewWriter(w)

	if err := writer.Write(deltaCSVHeader); err != nil {
		requestLogger.Warnw("Can't write delta CSV header", zap.Error(err))

		return
	}

	streamErr := h.services.Delta.StreamChangeEvents(ctx, scanID, func(event *deltarepository.ChangeEvent) error {
		details := ""

		if len(event.Details) > 0 {
			raw, marshalErr := json.Marshal(event.Details)
			if marshalErr == nil {
				details = string(raw)
			}
		}

		row := []string{
			strconv.FormatUint(event.ID, 10),
			strconv.FormatUint(event.ScanID, 10),
			strconv.FormatUint(event.HostID, 10),
			nullInt64String(event.ServiceID),
			nullInt64String(event.PreviousScanID),
			csvSafe(string(event.ChangeType)),
			csvSafe(details),
			event.CreatedAt.Format(time.RFC3339),
		}

		if err := writer.Write(row); err != nil {
			return err
		}

		if flusher != nil {
			writer.Flush()
			flusher.Flush()
		}

		return nil
	})

	writer.Flush()

	if streamErr != nil {
		requestLogger.Warnw("Delta CSV stream interrupted",
			zap.Uint64("scan_id", scanID),
			zap.Error(streamErr),
		)
	}
}

func nullInt64String(v sql.NullInt64) string {
	if !v.Valid {
		return ""
	}

	return strconv.FormatInt(v.Int64, 10)
}

func (h *Router) registerExportAPI(api *apiRouter) {
	h.registerProtectedRoutes(api, []protectedRoute{
		{
			http.MethodGet,
			"/export/scans/{id}/delta.csv",
			[]auth.Role{auth.RoleViewer, auth.RoleOperator},
			h.exportDeltaCSVHandler,
		},
	})
}
