export type AuditEvent = {
  id: number;
  user_id?: number | null;
  actor_role?: string | null;
  actor_ip?: string | null;
  method: string;
  path: string;
  status_code: number;
  resource_id?: string | null;
  user_agent?: string | null;
  created_at: string;
};

export type AuditListResponse = {
  page: number;
  limit: number;
  total: number;
  items: AuditEvent[];
};

export type AuditStatusFamily = '2xx' | '3xx' | '4xx' | '5xx';

export type AuditListParams = {
  page: number;
  limit: number;
  method?: string;
  status_family?: AuditStatusFamily;
  q?: string;
  user_id?: number;
  since?: string;
  until?: string;
};
