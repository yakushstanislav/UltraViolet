package handler

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
)

// PageResponse is the canonical paginated list envelope used across all
// /v1/* list endpoints.
type PageResponse[T any] struct {
	Page  uint64 `json:"page"`
	Limit uint64 `json:"limit"`
	Total uint64 `json:"total"`
	Items []T    `json:"items"`
}

// NewPageResponse builds a PageResponse with a non-nil Items slice.
func NewPageResponse[T any](page, limit, total uint64, items []T) PageResponse[T] {
	if items == nil {
		items = []T{}
	}

	return PageResponse[T]{
		Page:  page,
		Limit: limit,
		Total: total,
		Items: items,
	}
}

func (h *Router) sendJSONResponse(w http.ResponseWriter, status int, data any) {
	response, err := json.Marshal(data)
	if err != nil {
		if h.logger != nil {
			h.logger.Errorw("Can't marshal HTTP response", zap.Error(err))
		}

		httperror.WriteCode(w, h.logger, http.StatusInternalServerError, httperror.CodeInternal)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if _, err := w.Write(response); err != nil && h.logger != nil {
		h.logger.Errorw("Can't send HTTP response", zap.Error(err))
	}
}
