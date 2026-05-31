package handler

import (
	"net/http"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/buildinfo"
)

type versionResponse struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	DemoMode bool   `json:"demo_mode"`
}

func (h *Router) versionHandler(w http.ResponseWriter, _ *http.Request) {
	h.sendJSONResponse(w, http.StatusOK, versionResponse{
		Version:  buildinfo.Version,
		Commit:   buildinfo.Commit,
		DemoMode: h.config.DemoMode,
	})
}
