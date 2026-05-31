import { type ReactNode } from 'react';

export type MobileTab = {
  key: string;
  label: ReactNode;
  icon?: ReactNode;
};

type MobileTabsProps = {
  tabs: MobileTab[];
  activeKey: string;
  onChange: (key: string) => void;
  ariaLabel?: string;
  className?: string;
};

export function MobileTabs({
  tabs,
  activeKey,
  onChange,
  ariaLabel,
  className,
}: MobileTabsProps) {
  return (
    <div
      aria-label={ariaLabel}
      className={`uv-mobile-tabs${className ? ' ' + className : ''}`}
      role="tablist"
    >
      {tabs.map((tab) => {
        const isActive = tab.key === activeKey;

        return (
          <button
            aria-selected={isActive}
            className={`uv-mobile-tabs__tab${isActive ? ' uv-mobile-tabs__tab--active' : ''}`}
            key={tab.key}
            onClick={() => onChange(tab.key)}
            role="tab"
            type="button"
          >
            {tab.icon && <span className="uv-mobile-tabs__icon">{tab.icon}</span>}
            <span className="uv-mobile-tabs__label">{tab.label}</span>
          </button>
        );
      })}
    </div>
  );
}
