import * as Popover from '@radix-ui/react-popover';
import { Activity, Calendar, ExternalLink, Globe } from 'lucide-react';
import {
  type ReactNode,
  useEffect,
  useRef,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { countryCodeToFlagEmoji } from '@helpers/countryFlagEmoji';
import { getHost } from '@services/HostAPI';
import type { Host } from '@/types/hosts';

import { SkeletonBar } from './Skeleton';

const HOVER_INTENT_DELAY = 250;
const TOP_SERVICES = 4;

const hostCache = new Map<string, Host>();
const inflight = new Map<string, Promise<Host>>();

function fetchHostCached(ip: string): Promise<Host> {
  const cached = hostCache.get(ip);
  if (cached) {
    return Promise.resolve(cached);
  }

  const pending = inflight.get(ip);
  if (pending) {
    return pending;
  }

  const promise = getHost(ip, { page: 1, limit: TOP_SERVICES })
    .then((host) => {
      hostCache.set(ip, host);
      inflight.delete(ip);
      return host;
    })
    .catch((err: unknown) => {
      inflight.delete(ip);
      throw err;
    });

  inflight.set(ip, promise);
  return promise;
}

type HostHoverCardProps = {
  ip: string;
  children: ReactNode;
};

export function HostHoverCard({ ip, children }: HostHoverCardProps) {
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const [host, setHost] = useState<Host | null>(() => hostCache.get(ip) ?? null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const intentTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const cancelIntent = () => {
    if (intentTimer.current !== null) {
      clearTimeout(intentTimer.current);
      intentTimer.current = null;
    }
  };

  const beginIntent = () => {
    cancelIntent();
    intentTimer.current = setTimeout(() => {
      setOpen(true);
    }, HOVER_INTENT_DELAY);
  };

  useEffect(() => {
    if (!open) {
      return;
    }

    const cached = hostCache.get(ip);
    if (cached) {
      setHost(cached);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    fetchHostCached(ip)
      .then((data) => {
        if (!cancelled) {
          setHost(data);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Load failed');
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, ip]);

  useEffect(() => () => cancelIntent(), []);

  const flag = host?.country_code ? countryCodeToFlagEmoji(host.country_code) : '';
  const country = host?.country_name ?? host?.country_code ?? '';
  const asnLabel =
    host?.asn !== undefined
      ? `AS${host.asn}${host.asn_org ? ' · ' + host.asn_org : ''}`
      : '';
  const lastSeen = host?.last_seen
    ? new Intl.DateTimeFormat(i18n.language, {
        dateStyle: 'medium',
        timeStyle: 'short',
      }).format(new Date(host.last_seen))
    : '';
  const services = host?.services?.slice(0, TOP_SERVICES) ?? [];

  return (
    <Popover.Root onOpenChange={setOpen} open={open}>
      <Popover.Trigger asChild>
        <span
          className="host-hover-trigger"
          onBlur={() => setOpen(false)}
          onFocus={beginIntent}
          onMouseEnter={beginIntent}
          onMouseLeave={() => {
            cancelIntent();
          }}
        >
          {children}
        </span>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="start"
          className="host-hover-card uv-anim-pop"
          collisionPadding={8}
          onMouseEnter={cancelIntent}
          onMouseLeave={() => setOpen(false)}
          side="bottom"
          sideOffset={6}
        >
          <div className="host-hover-card-head">
            <span className="host-hover-card-ip">{ip}</span>
            <Link
              className="host-hover-card-open"
              to={`/hosts/${encodeURIComponent(ip)}`}
            >
              {t('hostHoverCard.open')}
              <ExternalLink aria-hidden size={12} />
            </Link>
          </div>

          {loading && !host && (
            <div className="host-hover-card-body">
              <SkeletonBar size="long" />
              <SkeletonBar size="mid" />
              <SkeletonBar size="short" />
            </div>
          )}

          {error && !host && (
            <p className="host-hover-card-error">
              {t('hostHoverCard.error')}
            </p>
          )}

          {host && (
            <div className="host-hover-card-body">
              {(country || flag) && (
                <div className="host-hover-card-row">
                  <Globe aria-hidden size={13} />
                  <span>
                    {flag && (
                      <span className="host-hover-card-flag">{flag}</span>
                    )}
                    {country}
                  </span>
                </div>
              )}
              {asnLabel && (
                <div className="host-hover-card-row">
                  <Activity aria-hidden size={13} />
                  <span>{asnLabel}</span>
                </div>
              )}
              {lastSeen && (
                <div className="host-hover-card-row">
                  <Calendar aria-hidden size={13} />
                  <span>{lastSeen}</span>
                </div>
              )}
              {services.length > 0 && (
                <div className="host-hover-card-ports">
                  {services.map((service) => (
                    <span
                      className="host-hover-card-port"
                      key={service.id}
                      title={service.protocol ?? service.transport}
                    >
                      {service.port}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
