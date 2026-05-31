import type { ReactNode } from 'react';

type EmptyStateProps = {
  icon: ReactNode;
  title: string;
  hint?: string;
  action?: ReactNode;
};

export function EmptyState({ icon, title, hint, action }: EmptyStateProps) {
  return (
    <div className="empty-state" role="status">
      <span aria-hidden className="empty-state-icon">
        {icon}
      </span>
      <strong className="empty-state-title">{title}</strong>
      {hint !== undefined && hint !== '' && (
        <p className="empty-state-hint">{hint}</p>
      )}
      {action !== undefined && (
        <div className="empty-state-action">{action}</div>
      )}
    </div>
  );
}
