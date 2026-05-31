export type RiskBucket = 'low' | 'medium' | 'high' | 'critical';

export const RISK_BUCKETS: RiskBucket[] = ['low', 'medium', 'high', 'critical'];

export type BucketTone = 'green' | 'yellow' | 'orange' | 'red';

export function bucketTone(bucket: string | null | undefined): BucketTone {
  switch (bucket) {
    case 'critical':
      return 'red';
    case 'high':
      return 'orange';
    case 'medium':
      return 'yellow';
    default:
      return 'green';
  }
}

export function bucketForScore(score: number | null | undefined): RiskBucket {
  if (score == null) {
    return 'low';
  }

  if (score >= 80) {
    return 'critical';
  }

  if (score >= 60) {
    return 'high';
  }

  if (score >= 30) {
    return 'medium';
  }

  return 'low';
}

export type RiskExplainChannel = {
  code: string;
  label: string;
  p: number;
  sources?: string[];
};

export type RiskExplainImpact = {
  code: string;
  label: string;
  weight: number;
  contribution: number;
};

export type RiskExplainFactor = {
  code: string;
  label: string;
  weight: number;
};

export type RiskExplainConfidenceMeters = {
  completeness: number;
  recency: number;
  signal_quality: number;
  tag_completeness: number;
};

export type RiskExplainComponents = {
  max_service_risk: number;
  service_count: number;
  high_risk_service_count: number;
  kev_count: number;
  critical_cve_count: number;
  max_epss?: number;
  last_seen: string;
};

export type HostRiskExplain = {
  ip: string;
  risk_score: number;
  probability?: number;
  impact?: number;
  confidence?: number;
  bucket?: RiskBucket | string;
  updated_at?: string;
  factors: RiskExplainFactor[];
  channels?: RiskExplainChannel[];
  impacts?: RiskExplainImpact[];
  confidence_meters?: RiskExplainConfidenceMeters;
  components: RiskExplainComponents;
};

export type ServiceRiskExplain = {
  service_id: number;
  host_id: number;
  port: number;
  protocol?: string;
  probability: number;
  recency_factor: number;
  channels: RiskExplainChannel[];
};

export type RiskHistoryPoint = {
  captured_at: string;
  score: number;
  probability: number;
  impact: number;
  confidence: number;
};

export type RiskHistoryResponse = {
  ip: string;
  points: RiskHistoryPoint[];
};
