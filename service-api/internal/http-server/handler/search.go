package handler

import (
	"encoding/csv"
	"net/http"
	"strconv"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
)

const searchCSVMaxLimit uint64 = 10000

func (h *Router) searchHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	if r.URL.Query().Get("format") == "csv" {
		h.searchExportCSV(w, r)

		return
	}

	page, limit, offset, err := h.parsePagination(w, r)
	if err != nil {
		return
	}

	response, err := h.services.Search.Search(ctx, r.URL.Query(), page, limit, offset)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) searchExportCSV(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	response, err := h.services.Search.Search(ctx, r.URL.Query(), 1, searchCSVMaxLimit, 0)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"uv-search.csv\"")
	w.WriteHeader(http.StatusOK)

	writer := csv.NewWriter(w)

	header := []string{
		"service_id", "host_id", "ip", "port", "transport", "protocol",
		"country_code", "asn", "status_code", "server", "title", "risk_score",
	}

	if err := writer.Write(header); err != nil {
		requestLogger.Warnw("Can't write search CSV header", "error", err)

		return
	}

	for _, hit := range response.Hits {
		asn := ""
		if hit.ASN != nil {
			asn = strconv.FormatInt(*hit.ASN, 10)
		}

		statusCode := ""
		if hit.StatusCode != nil {
			statusCode = strconv.FormatInt(int64(*hit.StatusCode), 10)
		}

		row := []string{
			strconv.FormatUint(hit.ServiceID, 10),
			strconv.FormatUint(hit.HostID, 10),
			csvSafe(hit.IP),
			strconv.FormatUint(uint64(hit.Port), 10),
			csvSafe(hit.Transport),
			csvSafe(hit.Protocol),
			csvSafe(hit.CountryCode),
			asn,
			statusCode,
			csvSafe(hit.ServerHeader),
			csvSafe(hit.Title),
			strconv.Itoa(hit.RiskScore),
		}

		if err := writer.Write(row); err != nil {
			requestLogger.Warnw("Can't write search CSV row", "error", err)

			return
		}
	}

	writer.Flush()

	if err := writer.Error(); err != nil {
		requestLogger.Warnw("Can't flush search CSV", "error", err)
	}
}

func (h *Router) registerSearchAPI(api *apiRouter) {
	h.registerProtectedRoutes(api, []protectedRoute{
		{
			http.MethodGet,
			"/search",
			[]auth.Role{auth.RoleViewer, auth.RoleOperator},
			h.searchHandler,
		},
	})
}

// csvSafe neutralises cells that spreadsheet apps would treat as formulas.
// Attacker-controlled banner / title / header values can start with "=" or
// "+" and execute on open in Excel/LibreOffice; prefixing with a single
// quote disarms the cell while keeping the content readable.
func csvSafe(value string) string {
	if value == "" {
		return value
	}

	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	}

	return value
}
