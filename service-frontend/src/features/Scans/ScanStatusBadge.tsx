import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  PauseCircle,
  XCircle,
} from 'lucide-react';

import { statusClass } from '@helpers/format';
import type { ScanStatus } from '@/types/scans';

type ScanStatusBadgeProps = {
  status: ScanStatus;
  doneWithErrors?: boolean;
  flashed?: boolean;
};

export function ScanStatusBadge({
  status,
  doneWithErrors = false,
  flashed = false,
}: ScanStatusBadgeProps) {
  return (
    <span
      className={`${statusClass(status)} ${flashed ? 'status-event' : ''}`}
      title={status}
    >
      {status === 'FAILED' && (
        <XCircle aria-hidden className="scans-status-icon" size={14} />
      )}
      {status === 'DONE' && !doneWithErrors && (
        <CheckCircle2 aria-hidden className="scans-status-icon" size={14} />
      )}
      {status === 'DONE' && doneWithErrors && (
        <AlertTriangle
          aria-hidden
          className="scans-status-icon scans-status-icon-warn"
          size={14}
        />
      )}
      {status === 'CANCELED' && (
        <Ban aria-hidden className="scans-status-icon" size={14} />
      )}
      {status === 'PAUSED' && (
        <PauseCircle aria-hidden className="scans-status-icon" size={14} />
      )}
      {status}
    </span>
  );
}
