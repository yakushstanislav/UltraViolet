package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

const productElasticsearch = "elasticsearch"

func init() {
	Register(probeElasticsearch, 9200)
}

// probeElasticsearch performs an HTTP GET against the root path and parses
// the cluster info JSON to extract version, build flavour, and cluster
// name. Falls back to the raw HTTP response if the body is not Elastic-shaped.
func probeElasticsearch(ctx context.Context, s *Stack, target Target) (*Result, error) {
	httpRes, err := s.httpRequest(ctx, target, false)
	if err != nil {
		return nil, err
	}

	fp := &FingerprintResult{
		Product: productElasticsearch,
		RawJSON: mustMarshalJSON(map[string]any{
			"response": map[string]any{
				"status_code": httpRes.HTTP.StatusCode,
				"body":        httpRes.HTTP.Body,
			},
		}),
	}

	if httpRes.HTTP.StatusCode == http.StatusUnauthorized {
		authRequired := true
		fp.AuthRequired = &authRequired
	}

	if body := strings.TrimSpace(httpRes.HTTP.Body); body != "" {
		applyElasticRootInfo(fp, body)
	}

	return &Result{
		Target:      target,
		Protocol:    fp.Product,
		HTTP:        httpRes.HTTP,
		Fingerprint: fp,
	}, nil
}

// applyElasticRootInfo decodes the root cluster info document and copies
// the relevant fields into fp. No-op when the body doesn't look like
// Elasticsearch.
func applyElasticRootInfo(fp *FingerprintResult, body string) {
	var info struct {
		ClusterName string `json:"cluster_name"`
		ClusterUUID string `json:"cluster_uuid"`
		Tagline     string `json:"tagline"`
		Version     struct {
			Number      string `json:"number"`
			BuildFlavor string `json:"build_flavor"`
		} `json:"version"`
	}

	if json.Unmarshal([]byte(body), &info) != nil {
		return
	}

	looksLikeES := strings.Contains(info.Tagline, "Know, for Search") || info.ClusterUUID != ""
	if !looksLikeES {
		return
	}

	fp.Version = info.Version.Number
	fp.Edition = info.Version.BuildFlavor
	fp.ClusterName = info.ClusterName

	if fp.AuthRequired == nil {
		noAuth := false
		fp.AuthRequired = &noAuth
		fp.Anonymous = true
	}
}
