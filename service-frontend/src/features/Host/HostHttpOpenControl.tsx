import { ExternalLink } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Select } from '@components/Select';
import { getHost } from '@services/HostAPI';
import type { HostService } from '@/types/hosts';

import {
  buildHttpVisitUrl,
  collectHttpVisitTargets,
  defaultHttpVisitTargetId,
  formatHttpVisitSelectLabel,
  type HttpVisitTarget,
} from './hostServiceHelpers';

const hostHttpServicesMaxLimit = 1000;

type HostHttpOpenControlProps = {
  ip: string;
  services: HostService[];
  servicesTotal: number;
};

export function HostHttpOpenControl({
  ip,
  services,
  servicesTotal,
}: HostHttpOpenControlProps) {
  const { t } = useTranslation();
  const [targets, setTargets] = useState<HttpVisitTarget[]>([]);
  const [selectedServiceId, setSelectedServiceId] = useState<
    number | undefined
  >();

  useEffect(() => {
    const controller = new AbortController();

    if (servicesTotal === 0) {
      setTargets([]);

      return () => {
        controller.abort();
      };
    }

    if (services.length >= servicesTotal) {
      setTargets(collectHttpVisitTargets(services));

      return () => {
        controller.abort();
      };
    }

    const limit = Math.min(servicesTotal, hostHttpServicesMaxLimit);

    void getHost(ip, { page: 1, limit }, controller.signal)
      .then((host) => {
        if (controller.signal.aborted) {
          return;
        }

        setTargets(collectHttpVisitTargets(host.services ?? []));
      })
      .catch(() => {
        if (controller.signal.aborted) {
          return;
        }

        setTargets(collectHttpVisitTargets(services));
      });

    return () => {
      controller.abort();
    };
  }, [ip, services, servicesTotal]);

  useEffect(() => {
    if (targets.length === 0) {
      setSelectedServiceId(undefined);

      return;
    }

    setSelectedServiceId((current) => {
      if (
        current !== undefined &&
        targets.some((target) => target.serviceId === current)
      ) {
        return current;
      }

      return defaultHttpVisitTargetId(targets);
    });
  }, [targets]);

  if (targets.length === 0 || selectedServiceId === undefined) {
    return null;
  }

  const selectedTarget = targets.find(
    (target) => target.serviceId === selectedServiceId
  );
  if (selectedTarget === undefined) {
    return null;
  }

  const visitUrl = buildHttpVisitUrl(ip, selectedTarget);

  return (
    <div className="host-http-open">
      <div className="header-actions host-http-open-actions">
        <Select
          aria-label={t('hostPage.openInBrowser')}
          className="host-http-open-select"
          compact
          onChange={(next) => setSelectedServiceId(Number(next))}
          options={targets.map((target) => ({
            value: String(target.serviceId),
            label: formatHttpVisitSelectLabel(target),
          }))}
          value={String(selectedServiceId)}
        />
        <a
          className="button-secondary host-http-open-go"
          href={visitUrl}
          rel="noopener noreferrer"
          target="_blank"
        >
          {t('hostPage.openHttpPort')}
          <ExternalLink aria-hidden size={14} strokeWidth={2} />
        </a>
      </div>
    </div>
  );
}
