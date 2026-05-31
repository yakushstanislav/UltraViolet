package probe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const productGraphQL = "graphql"

// graphQLPaths lists the most commonly deployed GraphQL endpoint paths.
// They are tried in order; the first one that responds with a parseable
// GraphQL payload (data or errors envelope) wins.
var graphQLPaths = []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

// graphQLIntrospectionQuery is the minimum query that exposes the root
// Query type name when introspection is enabled.
const graphQLIntrospectionQuery = `{"query":"{__schema{queryType{name}}}"}`

// graphQLAuxResponseLimit caps the body we'll read while looking for a
// GraphQL response envelope. Real introspection responses are far larger,
// but the queryType name lives near the top of the JSON.
const graphQLAuxResponseLimit = 16 * 1024

// detectGraphQL probes the conventional GraphQL paths and returns a
// populated GraphQLResult when one of them speaks GraphQL. It performs at
// most one POST per path and stops on the first hit.
func (s *Stack) detectGraphQL(ctx context.Context, client *http.Client, scheme, addr string) *GraphQLResult {
	for _, path := range graphQLPaths {
		if gr := graphQLAttempt(ctx, client, scheme, addr, path, s.cfg.UserAgent); gr != nil {
			return gr
		}
	}

	return nil
}

// graphQLAttempt sends one introspection POST to the given path. Returns
// nil unless the response shape matches a GraphQL envelope.
func graphQLAttempt(ctx context.Context, client *http.Client, scheme, addr, path, userAgent string) *GraphQLResult {
	url := scheme + "://" + addr + path

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(graphQLIntrospectionQuery))
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, graphQLAuxResponseLimit))
	if err != nil || len(body) == 0 {
		return nil
	}

	var envelope struct {
		Data struct {
			Schema *struct {
				QueryType struct {
					Name string `json:"name"`
				} `json:"queryType"`
			} `json:"__schema"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}

	if jsonErr := json.Unmarshal(body, &envelope); jsonErr != nil {
		return nil
	}

	// Endpoint counts as GraphQL when either introspection succeeded or
	// the server returned the GraphQL errors envelope (e.g. introspection
	// blocked but otherwise valid GraphQL handler).
	if envelope.Data.Schema == nil && len(envelope.Errors) == 0 {
		return nil
	}

	result := &GraphQLResult{Endpoint: path}

	if envelope.Data.Schema != nil && envelope.Data.Schema.QueryType.Name != "" {
		result.IntrospectionEnabled = true
		result.QueryTypeName = envelope.Data.Schema.QueryType.Name
	}

	return result
}
