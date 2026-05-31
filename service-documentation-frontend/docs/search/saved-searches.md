# Saved Searches

A saved search is a named, reusable query. Use it for:

- Quick recall of frequent filters (e.g. "exposed RDP we own").
- The query backing of an alert rule.
- Sharing with operators on the same instance (saved searches are
  per-instance, not per-user).

## Creating

From the Search page, run a query and click **Save**. Give it a name.

From the API:

```bash
curl -s -X POST http://localhost:8080/v1/saved-searches \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "name":  "Exposed RDP in our space",
    "query": {
      "port":    [3389],
      "country": ["NL", "DE"]
    }
  }' | jq
```

Required role: `operator` or `admin`.

The `query` field is a jsonb object whose keys match the
[search parameters](/search/overview#url-parameters). The API does not
let you smuggle SQL in here — it deserialises into a strongly typed
struct.

## Listing

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/saved-searches?limit=50" | jq
```

Available to any authenticated role.

## Running

```bash
curl -s -X POST -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/saved-searches/12/run?limit=100" | jq
```

`run` executes the stored query against the current data. The result
shape is identical to `/v1/search`. Optional URL params (`limit`,
`offset`, `format=csv`) override the stored query's defaults.

## Deleting

```bash
curl -s -X DELETE -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/saved-searches/12"
```

Required role: `operator` or `admin`.

Deleting a saved search **does not** delete alert rules that reference
it — the alert worker reads the stored query at rule-create time and
copies the query into the alert rule at creation time. See [Alert Rules](/alerts/rules).

## UI

The Saved Searches page lists saved searches with URL-driven pagination
(`?page=` and `?limit=`, default 25). Each page shows:

- Name, query summary, last-run timestamp.
- A **Run** button that opens the Search page pre-populated.
- An **Open as alert** button (operator+) that scaffolds a new alert
  rule from the saved query.

The filter box narrows the rows on the **current page** only; use
pagination to browse the full library.
