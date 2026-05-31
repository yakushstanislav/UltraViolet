import { normalizeText, normalizeUpperText } from '@helpers/normalize';

import { Q_MODE_FUZZY, dateInputToRFC3339 } from './searchFormHelpers';

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 25;

export function buildSearchParamsFromForm(
  form: FormData,
  opts: { sort?: string; page?: number; limit?: number }
): URLSearchParams {
  const q = normalizeText(form.get('q'));
  const fuzzyMatch = form.get('q_mode') === 'on';
  const port = normalizeText(form.get('port'));
  const portFromRaw = normalizeText(form.get('port_from'));
  const portToRaw = normalizeText(form.get('port_to'));
  const country = normalizeUpperText(form.get('country'));
  const asn = normalizeText(form.get('asn'));
  const protocol = normalizeText(form.get('protocol'));
  const tls_issuer = normalizeText(form.get('tls_issuer'));
  const tls_fingerprint = normalizeText(form.get('tls_fingerprint'));
  const tls_subject = normalizeText(form.get('tls_subject'));
  const tls_san = normalizeText(form.get('tls_san'));
  const ssh = normalizeText(form.get('ssh'));
  const ssh_fingerprint = normalizeText(form.get('ssh_fingerprint'));
  const smtp = normalizeText(form.get('smtp'));
  const dns = normalizeText(form.get('dns'));
  const cve_id = normalizeUpperText(form.get('cve_id'));
  const cve_text = normalizeText(form.get('cve_text'));
  const riskScoreMinRaw = normalizeText(form.get('risk_score_min'));
  const riskScoreMaxRaw = normalizeText(form.get('risk_score_max'));
  const lastSeenFromRaw = normalizeText(form.get('last_seen_from'));
  const lastSeenToRaw = normalizeText(form.get('last_seen_to'));
  const confidenceGteRaw = normalizeText(form.get('confidence_gte'));

  const portFrom =
    portFromRaw !== '' && /^\d+$/.test(portFromRaw)
      ? Number(portFromRaw)
      : undefined;
  const portTo =
    portToRaw !== '' && /^\d+$/.test(portToRaw)
      ? Number(portToRaw)
      : undefined;
  const riskScoreMin =
    riskScoreMinRaw !== '' && /^\d+$/.test(riskScoreMinRaw)
      ? Number(riskScoreMinRaw)
      : undefined;
  const riskScoreMax =
    riskScoreMaxRaw !== '' && /^\d+$/.test(riskScoreMaxRaw)
      ? Number(riskScoreMaxRaw)
      : undefined;
  const confidenceGte =
    confidenceGteRaw !== '' && /^\d*(\.\d+)?$/.test(confidenceGteRaw)
      ? Number(confidenceGteRaw)
      : undefined;
  const cveSeverityRaw = form
    .getAll('cve_severity')
    .map((entry) =>
      typeof entry === 'string' ? entry.trim().toUpperCase() : ''
    )
    .filter((entry) => entry !== '')
    .join(',');

  const page = opts.page ?? DEFAULT_PAGE;
  const limit = opts.limit ?? DEFAULT_LIMIT;

  const next: Record<string, string | number | undefined> = {
    q,
    q_mode: fuzzyMatch ? Q_MODE_FUZZY : undefined,
    port,
    port_from: portFrom,
    port_to: portTo,
    country,
    asn,
    protocol,
    tls_issuer,
    tls_fingerprint,
    tls_subject,
    tls_san,
    ssh,
    ssh_fingerprint,
    smtp,
    dns,
    cve_id,
    cve_text,
    risk_score_min: riskScoreMin,
    risk_score_max: riskScoreMax,
    last_seen_from: dateInputToRFC3339(lastSeenFromRaw, false) || undefined,
    last_seen_to: dateInputToRFC3339(lastSeenToRaw, true) || undefined,
    has_cve: cveSeverityRaw ? 'true' : undefined,
    cve_severity: cveSeverityRaw || undefined,
    confidence_gte: confidenceGte,
    sort: opts.sort || undefined,
    page,
    limit,
  };

  const nextParams = new URLSearchParams();
  for (const [key, value] of Object.entries(next)) {
    if (value === undefined || value === '') {
      continue;
    }
    if (key === 'page' && value === DEFAULT_PAGE) {
      continue;
    }
    if (key === 'limit' && value === DEFAULT_LIMIT) {
      continue;
    }
    nextParams.set(key, String(value));
  }

  return nextParams;
}

export function searchPermalinkFromParams(params: URLSearchParams): string {
  const qs = params.toString();

  return `${window.location.origin}/search${qs !== '' ? `?${qs}` : ''}`;
}
