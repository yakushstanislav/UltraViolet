package handler

import "net/http"

func (h *Router) pingHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
