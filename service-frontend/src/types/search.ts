export type SearchHit = {
  service_id: number;
  host_id: number;
  ip: string;
  country_code?: string;
  asn?: number;
  port: number;
  transport: string;
  protocol?: string;
  status_code?: number;
  server?: string;
  title?: string;
  fragment?: string;
  risk_score?: number;
};

export type SearchResponse = {
  page: number;
  limit: number;
  total: number;
  hits: SearchHit[];
};
