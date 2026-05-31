/**
 * Structured form of a saved-search / alert query.
 * All optional; only set fields go into the persisted query JSON.
 */
export type SearchQuery = {
  q?: string;
  port?: string;
  port_from?: string;
  port_to?: string;
  country?: string;
  asn?: string;
  protocol?: string;
  tls_issuer?: string;
  tls_fingerprint?: string;
  sort?: string;
  has_cve?: string;
  cve_severity?: string;
  risk_score_min?: string;
  risk_score_max?: string;
  last_seen_from?: string;
  last_seen_to?: string;
  page?: number;
  limit?: number;
};
