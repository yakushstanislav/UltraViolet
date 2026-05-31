import { useTranslation } from 'react-i18next';

import type { HostHTTPSecurityInfo } from '../../types/hosts';

type Props = {
  info: HostHTTPSecurityInfo;
};

const formatHSTS = (info: HostHTTPSecurityInfo): string => {
  if (!info.hsts_max_age) {
    return '';
  }

  const parts: string[] = [`max-age=${info.hsts_max_age}`];

  if (info.hsts_include_subdomains) {
    parts.push('includeSubDomains');
  }

  if (info.hsts_preload) {
    parts.push('preload');
  }

  return parts.join('; ');
};

const formatCSP = (info: HostHTTPSecurityInfo, present: string): string => {
  if (!info.csp_present) {
    return '';
  }

  const flags: string[] = [present];

  if (info.csp_has_unsafe_inline) {
    flags.push("'unsafe-inline'");
  }

  if (info.csp_has_unsafe_eval) {
    flags.push("'unsafe-eval'");
  }

  return flags.join(' · ');
};

const formatCookieFlags = (info: HostHTTPSecurityInfo): string => {
  const parts: string[] = [];

  if (info.cookie_secure_count) {
    parts.push(`Secure×${info.cookie_secure_count}`);
  }

  if (info.cookie_httponly_count) {
    parts.push(`HttpOnly×${info.cookie_httponly_count}`);
  }

  if (info.cookie_samesite_strict_count) {
    parts.push(`SameSite=Strict×${info.cookie_samesite_strict_count}`);
  }

  if (info.cookie_samesite_lax_count) {
    parts.push(`SameSite=Lax×${info.cookie_samesite_lax_count}`);
  }

  if (info.cookie_samesite_none_count) {
    parts.push(`SameSite=None×${info.cookie_samesite_none_count}`);
  }

  return parts.join(' · ');
};

export const HttpSecurityInfoBlock = ({ info }: Props) => {
  const { t } = useTranslation();

  const hsts = formatHSTS(info);
  const csp = formatCSP(info, t('hostPage.present'));
  const cookies = formatCookieFlags(info);

  return (
    <div className="host-kv-grid">
      <span>{t('hostPage.hstsParsed')}</span>
      <strong className="cell-mono">
        {hsts || <span className="text-muted">{t('hostPage.absent')}</span>}
      </strong>

      <span>{t('hostPage.cspParsed')}</span>
      <strong className="cell-mono">
        {csp || <span className="text-muted">{t('hostPage.absent')}</span>}
      </strong>

      {info.referrer_policy && (
        <>
          <span>{t('hostPage.referrerPolicy')}</span>
          <strong className="cell-mono">{info.referrer_policy}</strong>
        </>
      )}

      {info.permissions_policy_present && (
        <>
          <span>{t('hostPage.permissionsPolicy')}</span>
          <strong>{t('hostPage.present')}</strong>
        </>
      )}

      {info.cors_allow_origin && (
        <>
          <span>{t('hostPage.corsAllowOrigin')}</span>
          <strong className="cell-mono">{info.cors_allow_origin}</strong>
        </>
      )}

      {cookies && (
        <>
          <span>{t('hostPage.cookieFlags')}</span>
          <strong className="cell-mono">{cookies}</strong>
        </>
      )}
    </div>
  );
};
