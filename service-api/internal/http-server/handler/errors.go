package handler

import (
	"context"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/apireason"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/pgkit"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/host"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/scan"
	userrepository "github.com/yakushstanislav/UltraViolet/service-api/internal/repositories/user"
	authservice "github.com/yakushstanislav/UltraViolet/service-api/internal/services/auth"
	scanservice "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scan"
	scanscheduleservice "github.com/yakushstanislav/UltraViolet/service-api/internal/services/scanschedule"
	searchservice "github.com/yakushstanislav/UltraViolet/service-api/internal/services/search"
	userservice "github.com/yakushstanislav/UltraViolet/service-api/internal/services/user"
)

// clientCanceled is the unofficial nginx code for a closed client connection.
// We use it so cancelled requests stay distinguishable in metrics from real
// 500s without leaking sensitive details to the client.
const clientCanceled = 499

// sendErrorResponse maps a domain error to the right HTTP status + wire code and
// writes the response. Internal errors are logged at error level.
func (h *Router) sendErrorResponse(w http.ResponseWriter, log *zap.SugaredLogger, err error) {
	if err == nil {
		return
	}

	switch {
	case errors.Is(err, context.Canceled):
		httperror.WriteCode(w, log, clientCanceled, httperror.CodeInternal)

		return
	case errors.Is(err, scan.ErrNotFound),
		errors.Is(err, host.ErrNotFound),
		errors.Is(err, scanscheduleservice.ErrNotFound),
		errors.Is(err, userrepository.ErrNotFound),
		errors.Is(err, pgkit.ErrNoRows):
		httperror.WriteCode(w, log, http.StatusNotFound, httperror.CodeNotFound)

		return
	case errors.Is(err, scan.ErrNotCancelable):
		httperror.WriteConflict(w, log, apireason.ScanNotCancelable)

		return
	case errors.Is(err, scan.ErrNotPauseable):
		httperror.WriteConflict(w, log, apireason.ScanNotPauseable)

		return
	case errors.Is(err, scan.ErrNotResumable):
		httperror.WriteConflict(w, log, apireason.ScanNotResumable)

		return
	case errors.Is(err, scan.ErrNotRestartable):
		httperror.WriteConflict(w, log, apireason.ScanNotRestartable)

		return
	case errors.Is(err, userservice.ErrUsernameTaken):
		httperror.WriteConflict(w, log, apireason.UserUsernameTaken)

		return
	case errors.Is(err, pgkit.ErrForeignKeyViolation),
		errors.Is(err, pgkit.ErrUniqueViolation):
		httperror.WriteCode(w, log, http.StatusConflict, httperror.CodeConflict)

		return
	case errors.Is(err, scanservice.ErrInvalidInput):
		httperror.WriteInvalidArgument(w, log, scanservice.InvalidInputAPIReason(err))

		return
	case errors.Is(err, searchservice.ErrInvalidFilters):
		httperror.WriteInvalidArgument(w, log, searchservice.InvalidFiltersAPIReason(err))

		return
	case errors.Is(err, authservice.ErrUnauthorized):
		httperror.WriteCode(w, log, http.StatusUnauthorized, httperror.CodeUnauthorized)

		return
	case errors.Is(err, userservice.ErrPolicyViolation):
		httperror.WriteInvalidArgument(w, log, userservice.PolicyViolationAPIReason(err))

		return
	}

	if log != nil {
		log.Errorw("HTTP request failed", zap.Error(err))
	}

	httperror.WriteCode(w, log, http.StatusInternalServerError, httperror.CodeInternal)
}

func (h *Router) sendResponse(w http.ResponseWriter, status int, code string) {
	httperror.WriteCode(w, h.logger, status, code)
}
