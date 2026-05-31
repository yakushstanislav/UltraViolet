import { extractDomainErrorMessage } from '@helpers/apiError';

/** Stable `reason` values from POST /v1/scans 400 responses (see service-api apireason). */
const SCAN_CREATE_ERROR_REASONS = [
  'scan_invalid_input',
  'scan_cidr_not_allowed',
  'scan_too_many_ports',
  'scan_too_many_hosts',
  'scan_invalid_cidr',
  'scan_invalid_port',
  'scan_syn_engine_ipv4_required',
  'scan_target_empty',
  'scan_target_resolve_failed',
  'scan_target_resolve_empty',
  'scan_random_limit_required',
  'scan_random_allowed_cidrs_unconfigured',
  'scan_random_limit_exceeds_max_hosts',
  'scan_country_geoip_required',
  'scan_country_no_prefixes',
  'scan_country_limit_required',
  'scan_ports_expr_empty',
  'scan_ports_expr_no_ports',
  'scan_ports_invalid_range_bounds',
  'scan_ports_expr_invalid',
] as const;

export function resolveScanCreateErrorMessage(
  error: unknown,
  fallback: string
): string {
  return extractDomainErrorMessage(error, {
    reasons: SCAN_CREATE_ERROR_REASONS,
    i18nPrefix: 'scans.apiReasons',
    fallback,
  });
}
