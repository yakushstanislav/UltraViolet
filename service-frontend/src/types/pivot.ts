export type PivotNodeKind = 'host' | 'service' | 'artifact';

export type PivotNode = {
  id: string;
  kind: PivotNodeKind;
  label: string;
  ip?: string;
  host_id?: number;
  service_id?: number;
  port?: number;
  transport?: string;
  protocol?: string;
  country_code?: string;
  risk_score?: number;
  title?: string;
};

export type PivotEdge = {
  source: string;
  target: string;
  kind: string;
};

export type PivotResponse = {
  kind: string;
  value: string;
  total: number;
  truncated: boolean;
  nodes: PivotNode[];
  edges: PivotEdge[];
};

export type HostRiskFactor = {
  code: string;
  label: string;
  weight: number;
};

export type HostRiskExplainComponents = {
  max_service_risk: number;
  service_count: number;
  high_risk_service_count: number;
  kev_count: number;
  max_epss?: number;
  critical_cve_count: number;
  last_seen: string;
};

export type HostRiskExplainChannel = {
  code: string;
  label: string;
  p: number;
  sources?: string[];
};

export type HostRiskExplainImpact = {
  code: string;
  label: string;
  weight: number;
  contribution: number;
};

export type HostRiskExplainConfidenceMeters = {
  completeness: number;
  recency: number;
  signal_quality: number;
  tag_completeness: number;
};

export type HostRiskExplainResponse = {
  ip: string;
  risk_score: number;
  probability?: number;
  impact?: number;
  confidence?: number;
  bucket?: string;
  updated_at?: string;
  factors: HostRiskFactor[];
  channels?: HostRiskExplainChannel[];
  impacts?: HostRiskExplainImpact[];
  confidence_meters?: HostRiskExplainConfidenceMeters;
  components: HostRiskExplainComponents;
};
