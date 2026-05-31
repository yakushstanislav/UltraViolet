import { zodResolver } from '@hookform/resolvers/zod';
import {
  ArrowDownToLine,
  BarChart2,
  Clock,
  History,
  Minus,
  Plus,
  Scale,
  ShieldAlert,
  Sliders,
  Save,
  Undo2,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  useController,
  useForm,
  useWatch,
  type Control,
  type FieldPath,
} from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';

import { ConfirmDialog } from '@components/ConfirmDialog';
import { InlineError } from '@components/InlineError';
import { SkeletonRow } from '@components/Skeleton';
import { StatTile, StatTileRow } from '@components/StatTile';
import { showActionError } from '@helpers/uiError';
import {
  riskPolicySchema,
  type RiskPolicyFormValues,
} from '@schemas/riskPolicy';
import { getRiskPolicy, updateRiskPolicy } from '@services/RiskPolicyAPI';

const DEFAULT_POLICY: RiskPolicyFormValues = {
  k_coefficient: 1,
  weight_blast: 0.2,
  weight_lateral: 0.1,
  kev_halflife_days: 90,
  epss_halflife_days: 30,
  recency_halflife_days: 7,
  tls_halflife_days: 30,
  kev_floor: 0.05,
  epss_floor: 0.02,
  recency_floor: 0.05,
  tls_floor: 0.05,
  untagged_impact_baseline: 0.35,
  untagged_confidence_cap: 0.55,
  high_risk_threshold: 65,
};

type FieldSpec = {
  field: FieldPath<RiskPolicyFormValues>;
  labelKey: string;
  descKey: string;
  min: number;
  max: number;
  step: number;
  unitKey?: string;
};

const COEFFICIENT_FIELDS: FieldSpec[] = [
  {
    field: 'k_coefficient',
    labelKey: 'risk.policy.kCoefficient',
    descKey: 'risk.policy.descK',
    min: 0.1,
    max: 20,
    step: 0.01,
  },
  {
    field: 'weight_blast',
    labelKey: 'risk.policy.weightBlast',
    descKey: 'risk.policy.descWeightBlast',
    min: 0,
    max: 1,
    step: 0.05,
  },
  {
    field: 'weight_lateral',
    labelKey: 'risk.policy.weightLateral',
    descKey: 'risk.policy.descWeightLateral',
    min: 0,
    max: 1,
    step: 0.05,
  },
];

const HALFLIFE_FIELDS: FieldSpec[] = [
  {
    field: 'kev_halflife_days',
    labelKey: 'risk.policy.kevHalflife',
    descKey: 'risk.policy.descKevHalflife',
    min: 1,
    max: 3650,
    step: 1,
  },
  {
    field: 'epss_halflife_days',
    labelKey: 'risk.policy.epssHalflife',
    descKey: 'risk.policy.descEpssHalflife',
    min: 1,
    max: 3650,
    step: 1,
  },
  {
    field: 'recency_halflife_days',
    labelKey: 'risk.policy.recencyHalflife',
    descKey: 'risk.policy.descRecencyHalflife',
    min: 1,
    max: 3650,
    step: 1,
  },
  {
    field: 'tls_halflife_days',
    labelKey: 'risk.policy.tlsHalflife',
    descKey: 'risk.policy.descTlsHalflife',
    min: 1,
    max: 3650,
    step: 1,
  },
];

const FLOOR_FIELDS: FieldSpec[] = [
  {
    field: 'kev_floor',
    labelKey: 'risk.policy.kevFloor',
    descKey: 'risk.policy.descKevFloor',
    min: 0,
    max: 1,
    step: 0.01,
  },
  {
    field: 'epss_floor',
    labelKey: 'risk.policy.epssFloor',
    descKey: 'risk.policy.descEpssFloor',
    min: 0,
    max: 1,
    step: 0.01,
  },
  {
    field: 'recency_floor',
    labelKey: 'risk.policy.recencyFloor',
    descKey: 'risk.policy.descRecencyFloor',
    min: 0,
    max: 1,
    step: 0.01,
  },
  {
    field: 'tls_floor',
    labelKey: 'risk.policy.tlsFloor',
    descKey: 'risk.policy.descTlsFloor',
    min: 0,
    max: 1,
    step: 0.01,
  },
];

const UNTAGGED_FIELDS: FieldSpec[] = [
  {
    field: 'untagged_impact_baseline',
    labelKey: 'risk.policy.untaggedImpact',
    descKey: 'risk.policy.descUntaggedImpact',
    min: 0,
    max: 1,
    step: 0.05,
  },
  {
    field: 'untagged_confidence_cap',
    labelKey: 'risk.policy.untaggedConfidenceCap',
    descKey: 'risk.policy.descUntaggedConfidenceCap',
    min: 0,
    max: 1,
    step: 0.05,
  },
  {
    field: 'high_risk_threshold',
    labelKey: 'risk.policy.highRiskThreshold',
    descKey: 'risk.policy.descHighRiskThreshold',
    min: 0,
    max: 100,
    step: 1,
  },
];

const WEIGHT_FIELDS: ReadonlyArray<FieldPath<RiskPolicyFormValues>> = [
  'weight_blast',
  'weight_lateral',
];

const GROUPS: ReadonlyArray<{
  titleKey: string;
  descKey: string;
  icon: typeof Sliders;
  fields: FieldSpec[];
}> = [
  {
    titleKey: 'risk.policy.groupCoefficients',
    descKey: 'risk.policy.groupDescCoefficients',
    icon: Sliders,
    fields: COEFFICIENT_FIELDS,
  },
  {
    titleKey: 'risk.policy.groupHalflives',
    descKey: 'risk.policy.groupDescHalflives',
    icon: Clock,
    fields: HALFLIFE_FIELDS,
  },
  {
    titleKey: 'risk.policy.groupFloors',
    descKey: 'risk.policy.groupDescFloors',
    icon: ArrowDownToLine,
    fields: FLOOR_FIELDS,
  },
  {
    titleKey: 'risk.policy.groupUntagged',
    descKey: 'risk.policy.groupDescUntagged',
    icon: ShieldAlert,
    fields: UNTAGGED_FIELDS,
  },
];

export function RiskPolicyPage() {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [serverSnapshot, setServerSnapshot] =
    useState<RiskPolicyFormValues | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  const [confirmRevert, setConfirmRevert] = useState(false);
  const form = useForm<RiskPolicyFormValues>({
    resolver: zodResolver(riskPolicySchema),
    defaultValues: DEFAULT_POLICY,
    mode: 'onChange',
  });

  useEffect(() => {
    setLoading(true);
    setLoadError(null);

    getRiskPolicy()
      .then((policy) => {
        setServerSnapshot(policy);
        form.reset(policy);
      })
      .catch((err) => {
        setLoadError(t('common.loadFailed'));
        showActionError(err, 'common.loadFailed');
      })
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [t]);

  useEffect(() => {
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      if (!form.formState.isDirty) {
        return;
      }

      event.preventDefault();
      event.returnValue = '';
    };

    window.addEventListener('beforeunload', onBeforeUnload);

    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [form.formState.isDirty]);

  const handleSubmit = async (values: RiskPolicyFormValues) => {
    try {
      const next = await updateRiskPolicy(values);
      form.reset(next);
      setServerSnapshot(next);
      toast.success(t('risk.policy.toastSaved'));
    } catch (err) {
      showActionError(err, 'common.saveFailed');
    }
  };

  const handleReset = () => {
    form.reset(DEFAULT_POLICY, { keepDefaultValues: true });
  };

  const handleRevert = () => {
    if (serverSnapshot != null) {
      form.reset(serverSnapshot, { keepDefaultValues: true });
    }
  };

  const handleNormalize = () => {
    const values = form.getValues();
    const sum = WEIGHT_FIELDS.reduce(
      (acc, f) => acc + (typeof values[f] === 'number' ? (values[f] as number) : 0),
      0,
    );

    if (sum === 0) {
      return;
    }

    WEIGHT_FIELDS.forEach((f) => {
      const current = typeof values[f] === 'number' ? (values[f] as number) : 0;
      form.setValue(f, Math.round((current / sum) * 10000) / 10000, {
        shouldDirty: true,
        shouldValidate: true,
      });
    });
  };

  const { isDirty, isValid, isSubmitting } = form.formState;

  const kValue = useWatch({ control: form.control, name: 'k_coefficient' });
  const weightValues = useWatch({
    control: form.control,
    name: ['weight_blast', 'weight_lateral'],
  });
  const threshold = useWatch({
    control: form.control,
    name: 'high_risk_threshold',
  });

  const weightSum = weightValues.reduce(
    (sum, w) => sum + (typeof w === 'number' ? w : 0),
    0,
  );
  const weightSumOk = Math.abs(weightSum - 1) < 0.001;

  return (
    <section className="page risk-policy-page">
      <div className="panel">
        <div className="panel-head risk-policy-head">
          <div>
            <h2>{t('risk.policy.title')}</h2>
            <p className="panel-subtitle">{t('risk.policy.subtitle')}</p>
          </div>
          {!loading && (
            <div className="header-actions">
              {!isValid ? (
                <span className="risk-policy-chip risk-policy-chip--warn">
                  {t('risk.policy.stateNeedsFix')}
                </span>
              ) : (
                isDirty && (
                  <span className="risk-policy-chip risk-policy-chip--dirty">
                    {t('risk.policy.stateDirty')}
                  </span>
                )
              )}
              <button
                className="secondary"
                onClick={() => setConfirmReset(true)}
                type="button"
              >
                <History aria-hidden size={16} />
                {t('risk.policy.reset')}
              </button>
              <button
                className="secondary"
                disabled={serverSnapshot == null || !isDirty}
                onClick={() => setConfirmRevert(true)}
                type="button"
              >
                <Undo2 aria-hidden size={16} />
                {t('risk.policy.revert')}
              </button>
              <button
                disabled={isSubmitting || !isDirty}
                form="risk-policy-form"
                type="submit"
              >
                <Save aria-hidden size={16} />
                {t('common.save')}
              </button>
            </div>
          )}
        </div>
      </div>

      {loadError != null && (
        <InlineError
          message={loadError}
          onRetry={() => window.location.reload()}
        />
      )}
      {loading && (
        <section className="panel">
          <table className="risk-events-table">
            <tbody>
              <SkeletonRow cells={['long', 'mid', 'short']} />
              <SkeletonRow cells={['mid', 'long', 'short']} />
              <SkeletonRow cells={['long', 'short', 'mid']} />
              <SkeletonRow cells={['mid', 'mid', 'long']} />
            </tbody>
          </table>
        </section>
      )}

      {!loading && loadError == null && (
        <StatTileRow>
          <StatTile
            icon={<Sliders size={18} />}
            label={t('risk.policy.kpiKCoefficient')}
            value={typeof kValue === 'number' ? kValue : '—'}
          />
          <StatTile
            icon={<BarChart2 size={18} />}
            label={t('risk.policy.kpiWeightSum')}
            tone={weightSumOk ? 'success' : 'warning'}
            value={weightSum.toFixed(2)}
          />
          <StatTile
            icon={<ShieldAlert size={18} />}
            label={t('risk.policy.kpiHighRisk')}
            value={typeof threshold === 'number' ? threshold : '—'}
          />
        </StatTileRow>
      )}

      {!loading && (
        <form
          className="risk-policy-form"
          id="risk-policy-form"
          onSubmit={form.handleSubmit(handleSubmit)}
        >
          {GROUPS.map((group, index) => {
            const Icon = group.icon;
            const headingId = `rp-group-${index}`;
            const isCoefficients =
              group.titleKey === 'risk.policy.groupCoefficients';

            return (
              <div
                aria-labelledby={headingId}
                className="panel risk-policy-group"
                key={group.titleKey}
                role="group"
              >
                <div className="risk-policy-group-head">
                  <Icon aria-hidden size={16} />
                  <span id={headingId}>{t(group.titleKey)}</span>
                </div>
                <p className="panel-subtitle risk-policy-group-desc">
                  {t(group.descKey)}
                </p>
                <div className="risk-policy-list">
                  {group.fields.map((spec) => (
                    <PolicyRow
                      key={spec.field}
                      control={form.control}
                      spec={spec}
                      savedValue={serverSnapshot?.[spec.field]}
                    />
                  ))}
                </div>
                {isCoefficients && !weightSumOk && (
                  <div className="risk-policy-normalize-row">
                    <button
                      className="secondary"
                      onClick={handleNormalize}
                      type="button"
                    >
                      <Scale aria-hidden size={14} />
                      {t('risk.policy.normalize')}
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </form>
      )}

      <ConfirmDialog
        confirmIcon={<History aria-hidden size={16} />}
        confirmLabel={t('risk.policy.reset')}
        description={t('risk.policy.confirmResetBody')}
        icon={<History aria-hidden size={18} />}
        onConfirm={handleReset}
        onOpenChange={setConfirmReset}
        open={confirmReset}
        title={t('risk.policy.confirmResetTitle')}
        tone="warning"
      />
      <ConfirmDialog
        confirmIcon={<Undo2 aria-hidden size={16} />}
        confirmLabel={t('risk.policy.revert')}
        description={t('risk.policy.confirmRevertBody')}
        icon={<Undo2 aria-hidden size={18} />}
        onConfirm={handleRevert}
        onOpenChange={setConfirmRevert}
        open={confirmRevert}
        title={t('risk.policy.confirmRevertTitle')}
        tone="warning"
      />
    </section>
  );
}

function valuesDiffer(a: number | undefined, b: number | undefined): boolean {
  if (a == null || b == null) {
    return false;
  }

  return Math.round(a * 10000) !== Math.round(b * 10000);
}

type PolicyRowProps = {
  control: Control<RiskPolicyFormValues>;
  spec: FieldSpec;
  savedValue: number | undefined;
};

function PolicyRow({ control, spec, savedValue }: PolicyRowProps) {
  const { t } = useTranslation();
  const {
    field: { value, onChange, onBlur, ref, name },
    fieldState: { error },
  } = useController({ control, name: spec.field });
  const changed = valuesDiffer(
    typeof value === 'number' ? value : undefined,
    savedValue,
  );

  const numValue = typeof value === 'number' ? value : undefined;

  const handleChange = (raw: string) => {
    if (raw === '') {
      onChange(undefined);

      return;
    }

    const next = Number(raw);
    onChange(Number.isFinite(next) ? next : undefined);
  };

  const handleStep = (delta: number) => {
    const base = numValue ?? spec.min;
    const next = Math.round((base + delta * spec.step) * 1e6) / 1e6;
    onChange(Math.min(spec.max, Math.max(spec.min, next)));
  };

  return (
    <div className="risk-policy-row">
      <div className="risk-policy-row-text">
        <span className="risk-policy-row-label">
          {t(spec.labelKey)}
          {changed && (
            <span
              className="risk-policy-changed-dot"
              title={t('risk.policy.changedMarker')}
            />
          )}
        </span>
        <span className="risk-policy-row-desc">{t(spec.descKey)}</span>
      </div>
      <div className="risk-policy-row-control">
        <div className={`risk-policy-stepper${error != null ? ' risk-policy-stepper--error' : ''}`}>
          <button
            aria-label={`${t(spec.labelKey)} decrease`}
            className="risk-policy-stepper-btn"
            disabled={numValue != null && numValue <= spec.min}
            onClick={() => handleStep(-1)}
            tabIndex={-1}
            type="button"
          >
            <Minus aria-hidden size={12} />
          </button>
          <input
            aria-label={t(spec.labelKey)}
            max={spec.max}
            min={spec.min}
            name={name}
            onBlur={onBlur}
            onChange={(event) => handleChange(event.target.value)}
            ref={ref}
            step={spec.step}
            type="number"
            value={numValue ?? ''}
          />
          <button
            aria-label={`${t(spec.labelKey)} increase`}
            className="risk-policy-stepper-btn"
            disabled={numValue != null && numValue >= spec.max}
            onClick={() => handleStep(1)}
            tabIndex={-1}
            type="button"
          >
            <Plus aria-hidden size={12} />
          </button>
        </div>
        {spec.unitKey != null && (
          <span className="risk-policy-unit">{t(spec.unitKey)}</span>
        )}
        {typeof error?.message === 'string' && (
          <span className="field-error risk-policy-row-error">
            {error.message}
          </span>
        )}
      </div>
    </div>
  );
}
