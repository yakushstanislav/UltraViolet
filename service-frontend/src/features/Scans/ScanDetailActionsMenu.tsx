import * as Popover from '@radix-ui/react-popover';
import {
  MoreHorizontal,
  Pause,
  Play,
  RotateCcw,
  StopCircle,
} from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { useDemoMode } from '@/hooks/useDemoMode';

import type { Scan } from '@/types/scans';

type ScanDetailActionsMenuProps = {
  scan: Scan;
  canPause: boolean;
  canStop: boolean;
  pausing: boolean;
  resuming: boolean;
  restarting: boolean;
  stopping: boolean;
  onPause: () => void;
  onResume: () => void;
  onRestart: () => void;
  onStop: () => void;
};

export function ScanDetailActionsMenu({
  scan,
  canPause,
  canStop,
  pausing,
  resuming,
  restarting,
  stopping,
  onPause,
  onResume,
  onRestart,
  onStop,
}: ScanDetailActionsMenuProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const demoMode = useDemoMode();

  const showPause =
    canPause && scan.status === 'RUNNING' && !scan.pause_requested;
  const showResume =
    canPause &&
    (scan.status === 'PAUSED' ||
      (scan.status === 'RUNNING' && scan.pause_requested));
  const showRestart =
    canPause &&
    (scan.status === 'DONE' ||
      scan.status === 'FAILED' ||
      scan.status === 'CANCELED' ||
      scan.status === 'PAUSED');
  const showStop =
    canStop &&
    (scan.status === 'PENDING' ||
      scan.status === 'RUNNING' ||
      scan.status === 'PAUSED');

  if (!showPause && !showResume && !showRestart && !showStop) {
    return null;
  }

  const pick = (action: () => void) => {
    setOpen(false);
    action();
  };

  return (
    <Popover.Root onOpenChange={setOpen} open={open}>
      <Popover.Trigger asChild>
        <button
          aria-label={t('shell.moreActions')}
          className="secondary scans-detail-actions-overflow topbar-icon-btn"
          type="button"
        >
          <MoreHorizontal aria-hidden size={16} />
          <span className="scans-detail-actions-overflow__label">
            {t('shell.moreActions')}
          </span>
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          className="role-select-menu scan-detail-actions-menu"
          collisionPadding={12}
          side="bottom"
          sideOffset={6}
        >
          <div className="role-select-menu-inner" role="menu">
            {showPause && (
              <button
                className="role-select-option"
                disabled={pausing || demoMode}
                onClick={() => pick(onPause)}
                role="menuitem"
                type="button"
              >
                <span className="role-select-option-label">
                  <Pause aria-hidden size={14} />
                  {t('scanDetail.pauseScan')}
                </span>
              </button>
            )}
            {showResume && (
              <button
                className="role-select-option"
                disabled={resuming || demoMode}
                onClick={() => pick(onResume)}
                role="menuitem"
                type="button"
              >
                <span className="role-select-option-label">
                  <Play aria-hidden size={14} />
                  {scan.status === 'RUNNING' && scan.pause_requested
                    ? t('scanDetail.cancelPause')
                    : t('scanDetail.resumeScan')}
                </span>
              </button>
            )}
            {showRestart && (
              <button
                className="role-select-option"
                disabled={restarting || demoMode}
                onClick={() => pick(onRestart)}
                role="menuitem"
                type="button"
              >
                <span className="role-select-option-label">
                  <RotateCcw aria-hidden size={14} />
                  {t('scanDetail.restartScan')}
                </span>
              </button>
            )}
            {showStop && (
              <button
                className="role-select-option"
                disabled={stopping || scan.cancel_requested === true || demoMode}
                onClick={() => pick(onStop)}
                role="menuitem"
                type="button"
              >
                <span className="role-select-option-label">
                  <StopCircle aria-hidden size={14} />
                  {scan.cancel_requested
                    ? t('scanDetail.stopping')
                    : t('scanDetail.stopScan')}
                </span>
              </button>
            )}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
