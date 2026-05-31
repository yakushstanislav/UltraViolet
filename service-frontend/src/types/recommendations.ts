export type Recommendation = {
  id: number;
  host_id: number;
  service_id?: number;
  action_code: string;
  label: string;
  expected_delta_p: number;
  expected_delta_score: number;
  evidence?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type RecommendationsResponse = {
  ip: string;
  recommendations: Recommendation[];
};
