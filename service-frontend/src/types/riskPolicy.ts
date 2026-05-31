export type RiskPolicy = {
  k_coefficient: number;
  weight_blast: number;
  weight_lateral: number;
  kev_halflife_days: number;
  epss_halflife_days: number;
  recency_halflife_days: number;
  tls_halflife_days: number;
  kev_floor: number;
  epss_floor: number;
  recency_floor: number;
  tls_floor: number;
  untagged_impact_baseline: number;
  untagged_confidence_cap: number;
  high_risk_threshold: number;
};
