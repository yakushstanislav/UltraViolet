import { useTranslation } from 'react-i18next';

import type { HostTLSFinding } from '../../types/hosts';

type Props = {
  findings: HostTLSFinding[];
};

const severityChipClass = (severity: string): string => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'severity-chip severity-chip-critical';
    case 'high':
      return 'severity-chip severity-chip-high';
    case 'medium':
      return 'severity-chip severity-chip-medium';
    case 'low':
      return 'severity-chip severity-chip-low';
    default:
      return 'severity-chip';
  }
};

const severityWeight: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const sortedFindings = (findings: HostTLSFinding[]): HostTLSFinding[] =>
  [...findings].sort((a, b) => {
    const wa = severityWeight[a.severity.toLowerCase()] ?? 99;
    const wb = severityWeight[b.severity.toLowerCase()] ?? 99;

    return wa - wb;
  });

export const TlsFindingsBlock = ({ findings }: Props) => {
  const { t } = useTranslation();

  if (findings.length === 0) {
    return null;
  }

  return (
    <details className="host-disclosure">
      <summary className="host-disclosure-summary">
        <span className="host-disclosure-leading">
          {t('hostPage.tlsFindings')}
          <span className="host-disclosure-badge">{findings.length}</span>
        </span>
      </summary>
      <div className="host-disclosure-panel">
        <ul className="tls-findings-list">
          {sortedFindings(findings).map((f, idx) => (
            <li className="tls-findings-item" key={`${f.code}-${idx}`}>
              <span className={severityChipClass(f.severity)}>
                {f.severity}
              </span>
              <strong className="cell-mono">{f.code}</strong>
              {f.detail && (
                <span className="text-muted tls-findings-detail">
                  {f.detail}
                </span>
              )}
            </li>
          ))}
        </ul>
      </div>
    </details>
  );
};
