import * as Popover from '@radix-ui/react-popover';
import { AlertTriangle, ChevronDown, Plus, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { FieldLabel } from '@components/FieldLabel';
import { Tooltip } from '@components/Tooltip';
import { fieldAria, fieldErrorId } from '@helpers/formField';
import { SearchableCountrySelect } from '@features/Search/SearchableCountrySelect';

import {
  SCAN_PORT_PRESET_GROUPS,
  countPorts,
} from './portPresets';
import {
  ENGINE_OPTION_DEFS,
  SLOW_PROFILE_DEFS,
  TARGET_STRATEGY_DEFS,
} from './scanCreateOptions';
import { TargetCombobox } from './TargetCombobox';
import type { ScanCreateFormHandle } from './useScanCreateForm';

type ScanCreateFormBodyProps = {
  scanForm: ScanCreateFormHandle;
};

export function ScanCreateFormBody({ scanForm }: ScanCreateFormBodyProps) {
  const { t } = useTranslation();
  const {
    form,
    modeWatch,
    slowProfileWatch,
    targetStrategyWatch,
    targetHint,
    recentTargets,
    targetField,
    countryField,
    portRanges,
    rangeErrors,
    portsExprWatch,
    activePreset,
    synTargetHint,
    portsMode,
    presetPopoverOpen,
    setPresetPopoverOpen,
    selectedPresetIds,
    scanDialogContentEl,
    presetPopoverTriggerLabel,
    togglePresetById,
    clearPortPreset,
    customizePortPreset,
  } = scanForm;

  return (
    <div className="scan-form-body">
      <div className="scan-form-section scan-form-section--main">
        <div className="scan-form-grid">
          <div className="scan-form-col scan-form-col--left">
            <label>
              {t('scansPage.name')}
              <input
                type="text"
                {...form.register('name')}
                placeholder={t('scansPage.namePlaceholder')}
              />
            </label>
            <div className="scan-field-group">
              <span className="scan-field-label">
                {t('scansPage.targetStrategy')}
              </span>
              <div
                aria-label={t('scansPage.targetStrategy')}
                className="scan-segmented"
                role="group"
              >
                {TARGET_STRATEGY_DEFS.map((opt) => (
                  <label className="scan-segmented-option" key={opt.value}>
                    <input
                      type="radio"
                      value={opt.value}
                      {...form.register('targetStrategy')}
                    />
                    <span>{t(opt.labelKey)}</span>
                  </label>
                ))}
              </div>
              <p className="scan-field-hint muted-text">
                {(() => {
                  const def = TARGET_STRATEGY_DEFS.find(
                    (o) => o.value === targetStrategyWatch
                  );

                  return def !== undefined
                    ? t(def.descriptionKey)
                    : '\u00a0';
                })()}
              </p>
            </div>
            {targetStrategyWatch === 'random' ? (
              <label>
                <FieldLabel required>
                  {t('scansPage.hostLimitLabel')}
                </FieldLabel>
                <input
                  {...form.register('hostLimit', {
                    valueAsNumber: true,
                  })}
                  {...fieldAria(
                    'hostLimit',
                    Boolean(form.formState.errors.hostLimit)
                  )}
                  min={1}
                  placeholder={t('scansPage.hostLimitPlaceholder')}
                  required
                  type="number"
                />
                {form.formState.errors.hostLimit && (
                  <span
                    className="field-error"
                    id={fieldErrorId('hostLimit')}
                    role="alert"
                  >
                    {form.formState.errors.hostLimit.message ??
                      t('scansPage.invalidLimit')}
                  </span>
                )}
                <span className="field-hint field-hint-ok">
                  {t('scansPage.randomHostLimitHint')}
                </span>
              </label>
            ) : targetStrategyWatch === 'country' ? (
              <>
                <label>
                  <FieldLabel required>
                    {t('scansPage.countryLabel')}
                  </FieldLabel>
                  <SearchableCountrySelect
                    name="country"
                    onChange={countryField.field.onChange}
                    placeholder={t('scansPage.countryPlaceholder')}
                    showAny={false}
                    value={countryField.field.value ?? ''}
                  />
                  {form.formState.errors.country && (
                    <span
                      className="field-error"
                      role="alert"
                    >
                      {form.formState.errors.country.message ??
                        t('scans.validation.countryInvalid')}
                    </span>
                  )}
                </label>
                <label>
                  <FieldLabel required>
                    {t('scansPage.hostLimitLabel')}
                  </FieldLabel>
                  <input
                    {...form.register('hostLimit', {
                      valueAsNumber: true,
                    })}
                    {...fieldAria(
                      'hostLimit',
                      Boolean(form.formState.errors.hostLimit)
                    )}
                    min={1}
                    placeholder={t('scansPage.hostLimitPlaceholder')}
                    required
                    type="number"
                  />
                  {form.formState.errors.hostLimit && (
                    <span
                      className="field-error"
                      id={fieldErrorId('hostLimit')}
                      role="alert"
                    >
                      {form.formState.errors.hostLimit.message ??
                        t('scansPage.invalidLimit')}
                    </span>
                  )}
                  <span className="field-hint field-hint-ok">
                    {t('scansPage.countryLimitHint')}
                  </span>
                </label>
              </>
            ) : (
              <>
                <label>
                  <FieldLabel required>
                    {t('scansPage.targetLabelLong')}
                  </FieldLabel>
                  <TargetCombobox
                    ariaDescribedBy={
                      form.formState.errors.target
                        ? fieldErrorId('target')
                        : undefined
                    }
                    ariaInvalid={Boolean(form.formState.errors.target)}
                    inputRef={targetField.field.ref}
                    onBlur={targetField.field.onBlur}
                    onChange={targetField.field.onChange}
                    placeholder={t('scansPage.targetPlaceholder')}
                    suggestions={recentTargets}
                    value={targetField.field.value ?? ''}
                  />
                  {targetHint && (
                    <span className="field-hint field-hint-warn">
                      {targetHint}
                    </span>
                  )}
                  {form.formState.errors.target && (
                    <span
                      className="field-error"
                      id={fieldErrorId('target')}
                      role="alert"
                    >
                      {form.formState.errors.target.message ??
                        t('scansPage.invalidTarget')}
                    </span>
                  )}
                </label>
                <label className="dialog-checkbox-field">
                  <input {...form.register('scanSubnet')} type="checkbox" />
                  <span>{t('scansPage.scanWholeSubnet')}</span>
                </label>
              </>
            )}
          </div>
          <div className="scan-form-col scan-form-col--right">
            <div className="scan-field-group scan-engine-panel">
              <span className="scan-field-label">
                {t('scansPage.portDiscoveryEngine')}
              </span>
              <div
                aria-label={t('scansPage.portDiscoveryEngine')}
                className="scan-engine-cards"
                role="radiogroup"
              >
                {ENGINE_OPTION_DEFS.map((opt) => {
                  const Icon = opt.Icon;

                  return (
                    <label className="scan-engine-card" key={opt.value}>
                      <input
                        type="radio"
                        value={opt.value}
                        {...form.register('mode')}
                      />
                      <span className="scan-engine-card-surface">
                        <Icon
                          aria-hidden
                          className="scan-engine-card-icon"
                          size={22}
                          strokeWidth={1.75}
                        />
                        <span className="scan-engine-card-title">
                          {t(opt.labelKey)}
                        </span>
                        <span className="scan-engine-card-tagline">
                          {t(opt.taglineKey)}
                        </span>
                      </span>
                    </label>
                  );
                })}
              </div>
              <p className="scan-field-hint scan-engine-detail-hint muted-text">
                {(() => {
                  const def = ENGINE_OPTION_DEFS.find(
                    (o) => o.value === modeWatch
                  );

                  return def !== undefined
                    ? t(def.descriptionKey)
                    : '\u00a0';
                })()}
              </p>
            </div>
            {modeWatch === 'slow' ? (
              <div className="scan-field-group">
                <span className="scan-field-label">
                  {t('scansPage.slowProfile')}
                </span>
                <div
                  aria-label={t('scansPage.slowProfile')}
                  className="scan-segmented"
                  role="group"
                >
                  {SLOW_PROFILE_DEFS.map((opt) => (
                    <label className="scan-segmented-option" key={opt.value}>
                      <input
                        type="radio"
                        value={opt.value}
                        {...form.register('slowProfile')}
                      />
                      <span>{t(opt.labelKey)}</span>
                    </label>
                  ))}
                </div>
                <p className="scan-field-hint muted-text">
                  {(() => {
                    const def = SLOW_PROFILE_DEFS.find(
                      (o) => o.value === slowProfileWatch
                    );

                    return def !== undefined
                      ? t(def.descriptionKey)
                      : '\u00a0';
                  })()}
                </p>
                {slowProfileWatch === 'aggressive' && (
                  <p className="scan-field-warning">
                    <AlertTriangle size={14} aria-hidden />{' '}
                    {t('scansPage.aggressiveWarning')}
                  </p>
                )}
              </div>
            ) : null}
          </div>
        </div>
      </div>
      {synTargetHint ? (
        <div className="scan-form-section scan-form-section--hints">
          <div className="scan-modal-inline-hints">
            <p className="field-hint field-hint-warn">{synTargetHint}</p>
          </div>
        </div>
      ) : null}
      <div className="scan-form-section scan-form-section--ports">
        <div className="ports-range-header">
          <span className="ports-range-header-label">
            {t('scansPage.portRangesHeader')}
          </span>
          <Popover.Root
            modal={false}
            onOpenChange={setPresetPopoverOpen}
            open={presetPopoverOpen}
          >
            <div className="select-shell ports-preset-select-wrap">
              <Popover.Trigger asChild>
                <button
                  aria-expanded={presetPopoverOpen}
                  aria-haspopup="dialog"
                  aria-label={t('scansPage.portPresetsAria')}
                  className="ports-preset-trigger"
                  type="button"
                >
                  <span className="ports-preset-trigger-label">
                    {presetPopoverTriggerLabel}
                  </span>
                  <ChevronDown
                    aria-hidden
                    className="select-shell-chevron"
                    size={16}
                  />
                </button>
              </Popover.Trigger>
            </div>
            <Popover.Portal container={scanDialogContentEl ?? undefined}>
              <Popover.Content
                align="start"
                className="ports-preset-popover"
                collisionPadding={12}
                onOpenAutoFocus={(event) => event.preventDefault()}
                side="bottom"
                sideOffset={4}
              >
                <div className="ports-preset-popover-head">
                  {t('scansPage.portPresetsHead')}
                </div>
                <div
                  className="ports-preset-popover-scroll"
                  onWheel={(event) => event.stopPropagation()}
                >
                  {SCAN_PORT_PRESET_GROUPS.map((group) => (
                    <div
                      className="ports-preset-popover-group"
                      key={group.id}
                    >
                      <div className="ports-preset-popover-group-label">
                        {t(`scans.portPresets.groups.${group.id}`)}
                      </div>
                      <div className="ports-preset-popover-options">
                        {group.presets.map((preset) => (
                          <label
                            className="ports-preset-popover-option"
                            key={preset.id}
                            title={t(
                              `scans.portPresets.presets.${preset.id}.description`
                            )}
                          >
                            <input
                              checked={selectedPresetIds.includes(preset.id)}
                              className="ports-preset-popover-cb"
                              onChange={() => {
                                togglePresetById(preset.id);
                              }}
                              type="checkbox"
                            />
                            <span className="ports-preset-popover-option-text">
                              {t(
                                `scans.portPresets.presets.${preset.id}.label`
                              )}
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
                <p className="ports-preset-popover-foot muted-text">
                  {t('scansPage.portPresetsFoot')}
                </p>
              </Popover.Content>
            </Popover.Portal>
          </Popover.Root>
          {portsMode === 'custom' && (
            <button
              className="secondary ports-range-add-btn"
              onClick={() => portRanges.append({ from: 1, to: 65535 })}
              type="button"
            >
              <Plus size={16} />
              {t('scansPage.addRange')}
            </button>
          )}
        </div>
        {portsMode === 'preset' && activePreset ? (
          <div className="ports-preset-summary">
            <span aria-hidden className="ports-preset-summary-dot" />
            <div className="ports-preset-summary-body">
              <strong className="ports-preset-summary-title">
                {t('scansPage.presetSummaryTitle', {
                  label: t(
                    `scans.portPresets.presets.${activePreset.id}.label`
                  ),
                })}
              </strong>
              <span className="ports-preset-summary-meta muted-text">
                {t('scansPage.presetSummaryPorts', {
                  count: countPorts(activePreset.portsExpr),
                  ranges: activePreset.portsExpr.length,
                  rangeWord:
                    activePreset.portsExpr.length === 1
                      ? t('scansPage.rangeWordOne')
                      : t('scansPage.rangeWordMany'),
                })}
              </span>
            </div>
            <div className="ports-preset-summary-actions">
              <button
                className="secondary"
                onClick={customizePortPreset}
                type="button"
              >
                {t('scansPage.customizeRanges')}
              </button>
              <button
                className="secondary"
                onClick={clearPortPreset}
                type="button"
              >
                {t('scansPage.clearButton')}
              </button>
            </div>
          </div>
        ) : (
          <>
            {portsMode === 'custom' && selectedPresetIds.length >= 2 ? (
              <div className="ports-preset-merge-banner muted-text">
                {t('scansPage.mergedFrom', {
                  list: selectedPresetIds
                    .map((id) => t(`scans.portPresets.presets.${id}.label`))
                    .join(', '),
                  ports: countPorts(portsExprWatch ?? []),
                })}
              </div>
            ) : null}
            <div className="ports-range-list">
              {portRanges.fields.map((field, index) => {
                const fromErr = rangeErrors?.[index]?.from;
                const toErr = rangeErrors?.[index]?.to;

                return (
                  <div className="ports-range-card" key={field.id}>
                    <div className="ports-range-card-line">
                      <span aria-hidden className="ports-range-card-index">
                        {index + 1}
                      </span>
                      <input
                        aria-label={t('scansPage.fromPortAria', {
                          index: index + 1,
                        })}
                        className={fromErr ? 'input-error' : undefined}
                        {...form.register(`portsExpr.${index}.from`, {
                          valueAsNumber: true,
                        })}
                        {...fieldAria(
                          `portsExpr-${index}-from`,
                          Boolean(fromErr)
                        )}
                        max={65535}
                        min={1}
                        type="number"
                      />
                      <span
                        aria-hidden
                        className="ports-range-sep"
                        title={t('scansPage.through')}
                      >
                        –
                      </span>
                      <input
                        aria-label={t('scansPage.toPortAria', {
                          index: index + 1,
                        })}
                        className={toErr ? 'input-error' : undefined}
                        {...form.register(`portsExpr.${index}.to`, {
                          valueAsNumber: true,
                        })}
                        {...fieldAria(
                          `portsExpr-${index}-to`,
                          Boolean(toErr)
                        )}
                        max={65535}
                        min={1}
                        type="number"
                      />
                      <Tooltip
                        label={t('scansPage.removeRangeAria', {
                          index: index + 1,
                        })}
                      >
                        <button
                          aria-label={t('scansPage.removeRangeAria', {
                            index: index + 1,
                          })}
                          className="secondary ports-range-remove-btn"
                          disabled={portRanges.fields.length === 1}
                          onClick={() => portRanges.remove(index)}
                          type="button"
                        >
                          <X size={12} />
                        </button>
                      </Tooltip>
                    </div>
                    {(fromErr || toErr) && (
                      <div className="ports-range-card-errors">
                        {fromErr && (
                          <span
                            className="field-error"
                            id={fieldErrorId(`portsExpr-${index}-from`)}
                            role="alert"
                          >
                            {fromErr.message ?? t('scansPage.invalidPort')}
                          </span>
                        )}
                        {toErr && (
                          <span
                            className="field-error"
                            id={fieldErrorId(`portsExpr-${index}-to`)}
                            role="alert"
                          >
                            {toErr.message ?? t('scansPage.invalidRangeEnd')}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
        {typeof rangeErrors?.message === 'string' && (
          <span
            className="field-error"
            id={fieldErrorId('portsExpr')}
            role="alert"
          >
            {rangeErrors.message}
          </span>
        )}
      </div>
    </div>
  );
}
