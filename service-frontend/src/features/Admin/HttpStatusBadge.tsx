import { AlertTriangle, CheckCircle2, Info, XCircle } from 'lucide-react';
import type { ReactNode } from 'react';

type HttpStatusBadgeProps = {
  code: number;
};

function familyFor(code: number): '2xx' | '3xx' | '4xx' | '5xx' | 'other' {
  if (code >= 200 && code < 300) return '2xx';
  if (code >= 300 && code < 400) return '3xx';
  if (code >= 400 && code < 500) return '4xx';
  if (code >= 500 && code < 600) return '5xx';
  return 'other';
}

function iconFor(family: ReturnType<typeof familyFor>): ReactNode {
  switch (family) {
    case '2xx':
      return <CheckCircle2 aria-hidden size={12} />;
    case '3xx':
      return <Info aria-hidden size={12} />;
    case '4xx':
      return <AlertTriangle aria-hidden size={12} />;
    case '5xx':
      return <XCircle aria-hidden size={12} />;
    default:
      return null;
  }
}

export function HttpStatusBadge({ code }: HttpStatusBadgeProps) {
  const family = familyFor(code);

  return (
    <span className={`status http-status http-status-${family}`} title={String(code)}>
      {iconFor(family)}
      {code}
    </span>
  );
}
