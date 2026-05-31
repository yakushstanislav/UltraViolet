package handler

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	cvedto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/cve"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/logger"
	cvesvc "github.com/yakushstanislav/UltraViolet/service-api/internal/services/cve"
)

// cveIDPattern matches the canonical NVD identifier shape. Used to reject
// obvious junk on /v1/cves/{id} before sending a parameterised lookup to
// Postgres (no SQL injection risk, but a tight filter keeps audit logs and
// metrics free of garbage IDs).
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

func (h *Router) listServiceCVEsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	serviceID, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	items, err := h.services.CVE.ListForService(ctx, serviceID)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	if items == nil {
		items = []cvedto.ServiceCVE{}
	}

	h.sendJSONResponse(w, http.StatusOK, map[string]any{"items": items})
}

func (h *Router) getCVEHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	id := strings.ToUpper(r.PathValue("id"))
	if !cveIDPattern.MatchString(id) {
		h.sendResponse(w, http.StatusBadRequest, httperror.CodeParseURL)

		return
	}

	out, err := h.services.CVE.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, cvesvc.ErrNotFound) {
			h.sendResponse(w, http.StatusNotFound, httperror.CodeNotFound)

			return
		}

		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, out)
}

func (h *Router) cveSyncStatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestLogger := logger.UnpackContext(ctx)

	response, err := h.services.CVE.SyncStatus(ctx)
	if err != nil {
		h.sendErrorResponse(w, requestLogger, err)

		return
	}

	h.sendJSONResponse(w, http.StatusOK, response)
}

func (h *Router) registerCVEAPI(api *apiRouter) {
	read := []auth.Role{auth.RoleViewer, auth.RoleOperator}

	h.registerProtectedRoutes(api, []protectedRoute{
		{http.MethodGet, "/services/{id}/cves", read, h.listServiceCVEsHandler},
		{http.MethodGet, "/cves/{id}", read, h.getCVEHandler},
		{http.MethodGet, "/cve/sync-status", read, h.cveSyncStatusHandler},
	})
}
