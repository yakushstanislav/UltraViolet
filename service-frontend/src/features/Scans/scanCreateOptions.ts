import { Radar, Turtle, Zap, type LucideIcon } from 'lucide-react';

import type { ScanFormValues } from '@schemas/scan';

type ScanMode = ScanFormValues['mode'];
type SlowProfile = ScanFormValues['slowProfile'];
type TargetStrategy = ScanFormValues['targetStrategy'];

export type EngineOption = {
  value: ScanMode;
  labelKey: string;
  taglineKey: string;
  descriptionKey: string;
  Icon: LucideIcon;
};

export type SegmentOption<V extends string> = {
  value: V;
  labelKey: string;
  descriptionKey: string;
};

export const ENGINE_OPTION_DEFS: EngineOption[] = [
  {
    value: 'slow',
    labelKey: 'scansPage.engineSlow',
    taglineKey: 'scansPage.engineSlowTag',
    descriptionKey: 'scansPage.engineSlowDesc',
    Icon: Turtle,
  },
  {
    value: 'masscan',
    labelKey: 'scansPage.engineMasscan',
    taglineKey: 'scansPage.engineMasscanTag',
    descriptionKey: 'scansPage.engineMasscanDesc',
    Icon: Zap,
  },
  {
    value: 'zmap',
    labelKey: 'scansPage.engineZmap',
    taglineKey: 'scansPage.engineZmapTag',
    descriptionKey: 'scansPage.engineZmapDesc',
    Icon: Radar,
  },
];

export const SLOW_PROFILE_DEFS: SegmentOption<SlowProfile>[] = [
  {
    value: 'stealth',
    labelKey: 'scansPage.profileStealth',
    descriptionKey: 'scansPage.profileStealthDesc',
  },
  {
    value: 'balanced',
    labelKey: 'scansPage.profileBalanced',
    descriptionKey: 'scansPage.profileBalancedDesc',
  },
  {
    value: 'aggressive',
    labelKey: 'scansPage.profileAggressive',
    descriptionKey: 'scansPage.profileAggressiveDesc',
  },
];

export const TARGET_STRATEGY_DEFS: SegmentOption<TargetStrategy>[] = [
  {
    value: 'sequential',
    labelKey: 'scansPage.strategySequential',
    descriptionKey: 'scansPage.strategySequentialDesc',
  },
  {
    value: 'random',
    labelKey: 'scansPage.strategyRandom',
    descriptionKey: 'scansPage.strategyRandomDesc',
  },
  {
    value: 'country',
    labelKey: 'scansPage.strategyCountry',
    descriptionKey: 'scansPage.strategyCountryDesc',
  },
];
