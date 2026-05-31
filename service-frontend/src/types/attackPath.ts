export type AttackPathRelation = {
  src_host_id: number;
  dst_host_id: number;
  relation_type: string;
  strength: number;
  evidence?: Record<string, unknown>;
};

export type AttackPathHostScore = {
  host_id: number;
  centrality: number;
  pivot_score: number;
  reachable_critical_count: number;
  top_paths?: unknown;
  computed_at?: string;
};

export type AttackPathHostRef = {
  host_id: number;
  ip: string;
};

export type AttackPathView = {
  ip: string;
  score: AttackPathHostScore;
  hosts: AttackPathHostRef[];
  relations: AttackPathRelation[];
};
