import { zodResolver } from '@hookform/resolvers/zod';
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import {
  useController,
  useFieldArray,
  useForm,
  useWatch,
} from 'react-hook-form';

import { getSynEngineIPv4TargetHint } from '@helpers/scanCreateHints';
import { describeScanTargetIssue } from '@helpers/scanTargetHint';
import { generateRandomScanName } from '@helpers/randomScanName';
import { readRecentScanTargets } from '@helpers/recentScanTargets';
import { useFocusFirstError } from '@/hooks/useFocusFirstError';
import { createScanSchema, type ScanFormValues } from '@schemas/scan';

import { SCAN_CREATE_FORM_DEFAULTS } from './scanFormDefaults';
import {
  findMatchingPreset,
  findMatchingPresetSelection,
  mergePresetsByIds,
  portExprListsEqual,
} from './portPresets';

type UseScanCreateFormOptions = {
  open: boolean;
};

export function useScanCreateForm({ open }: UseScanCreateFormOptions) {
  const { t } = useTranslation();
  const schema = useMemo(() => createScanSchema(t), [t]);

  const form = useForm<ScanFormValues>({
    resolver: zodResolver(schema),
    defaultValues: SCAN_CREATE_FORM_DEFAULTS,
  });
  useFocusFirstError(form.formState.errors, form.formState.isSubmitted);

  const { reset, getValues, control } = form;
  const targetWatch = useWatch({ control, name: 'target', defaultValue: '' });
  const modeWatch = useWatch({ control, name: 'mode', defaultValue: 'slow' });
  const slowProfileWatch = useWatch({
    control,
    name: 'slowProfile',
    defaultValue: 'stealth',
  });
  const targetStrategyWatch = useWatch({
    control,
    name: 'targetStrategy',
    defaultValue: 'sequential',
  });
  const targetHint =
    targetStrategyWatch === 'sequential'
      ? describeScanTargetIssue(targetWatch ?? '', t)
      : null;
  const [recentTargets, setRecentTargets] = useState<string[]>([]);
  const targetField = useController({ control, name: 'target' });
  const countryField = useController({ control, name: 'country' });

  useEffect(() => {
    if (!open) {
      reset(SCAN_CREATE_FORM_DEFAULTS);

      return;
    }

    setRecentTargets(readRecentScanTargets());
    reset({
      ...SCAN_CREATE_FORM_DEFAULTS,
      name: generateRandomScanName(),
    });
  }, [open, reset]);

  const portRanges = useFieldArray({
    control: form.control,
    name: 'portsExpr',
  });
  const rangeErrors = form.formState.errors.portsExpr;
  const portsExprWatch = useWatch({
    control,
    name: 'portsExpr',
    defaultValue: getValues('portsExpr'),
  });
  const activePreset = useMemo(
    () => findMatchingPreset(portsExprWatch ?? []),
    [portsExprWatch]
  );
  const synTargetHint = useMemo(
    () =>
      getSynEngineIPv4TargetHint(
        modeWatch ?? 'slow',
        targetStrategyWatch ?? 'sequential',
        targetWatch ?? '',
        t
      ),
    [modeWatch, targetStrategyWatch, targetWatch, t]
  );
  const [portsMode, setPortsMode] = useState<'preset' | 'custom'>(() =>
    findMatchingPreset(getValues('portsExpr') ?? []) ? 'preset' : 'custom'
  );
  const [presetPopoverOpen, setPresetPopoverOpen] = useState(false);
  const [selectedPresetIds, setSelectedPresetIds] = useState<string[]>([]);
  const selectedPresetIdsRef = useRef<string[]>(selectedPresetIds);
  const [scanDialogContentEl, setScanDialogContentEl] =
    useState<HTMLDivElement | null>(null);

  useLayoutEffect(() => {
    selectedPresetIdsRef.current = selectedPresetIds;
  }, [selectedPresetIds]);

  const presetPopoverTriggerLabel = useMemo(() => {
    if (selectedPresetIds.length === 0) {
      return t('scansPage.portPresetsTrigger');
    }

    const labels = selectedPresetIds
      .map((id) => t(`scans.portPresets.presets.${id}.label`))
      .filter(Boolean) as string[];

    if (labels.length === 0) {
      return t('scansPage.portPresetsTrigger');
    }

    if (labels.length === 1) {
      return labels[0];
    }

    if (labels.length === 2) {
      return `${labels[0]}, ${labels[1]}`;
    }

    return t('scansPage.portPresetsMore', {
      first: labels[0],
      count: labels.length - 1,
    });
  }, [selectedPresetIds, t]);

  useEffect(() => {
    if (!open) {
      setPresetPopoverOpen(false);

      return;
    }

    const expr = getValues('portsExpr') ?? [];
    const matched = findMatchingPreset(expr);

    setPortsMode(matched ? 'preset' : 'custom');
    setSelectedPresetIds(
      matched ? [matched.id] : findMatchingPresetSelection(expr)
    );
  }, [open, getValues]);

  useEffect(() => {
    if (selectedPresetIds.length === 0) {
      return;
    }

    const merged = mergePresetsByIds(selectedPresetIds);

    if (!portExprListsEqual(portsExprWatch ?? [], merged)) {
      selectedPresetIdsRef.current = [];
      setSelectedPresetIds([]);
    }
  }, [portsExprWatch, selectedPresetIds]);

  const applyPresetSelectionIds = useCallback(
    (nextIds: string[]) => {
      const deduped = [...new Set(nextIds)].filter(Boolean);
      const ids = deduped.includes('full') ? ['full'] : deduped;

      setSelectedPresetIds(ids);
      selectedPresetIdsRef.current = ids;

      if (ids.length === 0) {
        setPortsMode('custom');
      } else {
        const merged = mergePresetsByIds(ids);

        form.setValue('portsExpr', merged, {
          shouldDirty: true,
          shouldValidate: true,
        });
        setPortsMode(findMatchingPreset(merged) ? 'preset' : 'custom');
      }
    },
    [form]
  );

  const togglePresetById = useCallback(
    (id: string) => {
      const prev = selectedPresetIdsRef.current;

      applyPresetSelectionIds(
        prev.includes(id)
          ? prev.filter((x) => x !== id)
          : id === 'full'
            ? ['full']
            : [...prev.filter((x) => x !== 'full'), id]
      );
    },
    [applyPresetSelectionIds]
  );

  const clearPortPreset = useCallback(() => {
    form.setValue('portsExpr', [{ from: 1, to: 65535 }], {
      shouldDirty: true,
      shouldValidate: true,
    });
    setPortsMode('custom');
    setSelectedPresetIds([]);
    selectedPresetIdsRef.current = [];
  }, [form]);

  const customizePortPreset = useCallback(() => {
    setPortsMode('custom');
    setSelectedPresetIds([]);
    selectedPresetIdsRef.current = [];
  }, []);

  return {
    form,
    targetWatch,
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
    setScanDialogContentEl,
    presetPopoverTriggerLabel,
    togglePresetById,
    clearPortPreset,
    customizePortPreset,
  };
}

export type ScanCreateFormHandle = ReturnType<typeof useScanCreateForm>;
