package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"

	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/httperror"
)

const (
	defaultQueryLimit   = 100
	maxQueryLimit       = 1000
	defaultQueryPage    = 1
	maxQueryPage        = 1_000_000
	requestBodyMaxBytes = 64 * 1024
)

// errInvalidArgument is returned by request helpers when they have already
// written a 400 response. Callers use it as a signal to abort.
var errInvalidArgument = errors.New("invalid argument")

func parseUint64FromQuery(r *http.Request, key string, defaultValue uint64) (uint64, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("can't parse %s: %w", key, err)
	}

	return value, nil
}

func parseUint64FromPath(r *http.Request, key string) (uint64, error) {
	raw := r.PathValue(key)
	if raw == "" {
		return 0, errors.New("missing path var")
	}

	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("can't parse %s: %w", key, err)
	}

	return id, nil
}

// parsePagination extracts (page, limit, offset) from query params. On
// validation failure it already wrote a 400 response and returns
// errInvalidArgument.
func (h *Router) parsePagination(w http.ResponseWriter, r *http.Request) (uint64, uint64, uint64, error) {
	page, err := parseUint64FromQuery(r, "page", defaultQueryPage)
	if err != nil || page == 0 || page > maxQueryPage {
		httperror.WriteCode(w, h.logger, http.StatusBadRequest, httperror.CodeParseURL)

		return 0, 0, 0, errInvalidArgument
	}

	limit, err := parseUint64FromQuery(r, "limit", defaultQueryLimit)
	if err != nil || limit > maxQueryLimit {
		httperror.WriteCode(w, h.logger, http.StatusBadRequest, httperror.CodeParseURL)

		return 0, 0, 0, errInvalidArgument
	}

	if limit == 0 {
		limit = defaultQueryLimit
	}

	if page-1 > math.MaxUint64/limit {
		httperror.WriteCode(w, h.logger, http.StatusBadRequest, httperror.CodeParseURL)

		return 0, 0, 0, errInvalidArgument
	}

	offset := (page - 1) * limit

	return page, limit, offset, nil
}

// decodeBody decodes a JSON request body into dst with a strict, bounded reader.
// It returns an error on parse failure or trailing bytes; the caller is
// responsible for writing the HTTP response. The internal sentinel
// errRequestTooLarge lets callers map a payload-too-large failure to a
// 413 response code rather than the generic 400 they'd otherwise use.
func (h *Router) decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, requestBodyMaxBytes)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return errRequestTooLarge
		}

		return err
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must be a single JSON object")
	}

	return nil
}

// errRequestTooLarge is returned by decodeBody when MaxBytesReader rejected
// the body. writeDecodeError maps it to a 413 instead of the generic 400 so
// clients can tell payload-size errors apart from JSON parse failures.
var errRequestTooLarge = errors.New("request body too large")

// writeDecodeError maps a decodeBody error to the right HTTP status + code:
// a too-large body becomes 413 + CodeRequestTooLarge, anything else stays
// 400 + CodeParseBody so existing client expectations don't change.
func (h *Router) writeDecodeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRequestTooLarge) {
		httperror.WriteCode(w, h.logger, http.StatusRequestEntityTooLarge, httperror.CodeRequestTooLarge)

		return
	}

	httperror.WriteCode(w, h.logger, http.StatusBadRequest, httperror.CodeParseBody)
}
