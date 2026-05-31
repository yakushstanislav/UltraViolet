import { z } from 'zod';

const unit = z.number().min(0).max(1);
const halflife = z.number().int().min(1).max(3650);

export const riskPolicySchema = z.object({
  k_coefficient: z.number().min(0.1).max(20),
  weight_blast: unit,
  weight_lateral: unit,
  kev_halflife_days: halflife,
  epss_halflife_days: halflife,
  recency_halflife_days: halflife,
  tls_halflife_days: halflife,
  kev_floor: unit,
  epss_floor: unit,
  recency_floor: unit,
  tls_floor: unit,
  untagged_impact_baseline: unit,
  untagged_confidence_cap: unit,
  high_risk_threshold: z.number().int().min(0).max(100),
});

export type RiskPolicyFormValues = z.infer<typeof riskPolicySchema>;
