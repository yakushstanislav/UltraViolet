import type { SearchQuery } from './common';

export type AlertRule = {
  id: number;
  name: string;
  saved_search_id?: number;
  query?: SearchQuery;
  channel: string;
  destination?: string;
  cooldown_sec: number;
  enabled: boolean;
  last_fired_at?: string;
  created_at: string;
  updated_at: string;
};

export type AlertEvent = {
  id: number;
  rule_id: number;
  hits_count: number;
  // Backend-agnostic snapshot of the matched hits; shape depends on the rule's query.
  payload?: Record<string, unknown>;
  created_at: string;
};

export type AlertListResponse = {
  page: number;
  limit: number;
  total: number;
  items: AlertRule[];
};

export type AlertEventsResponse = {
  page: number;
  limit: number;
  total: number;
  items: AlertEvent[];
};

export type CreateAlertRequest = {
  name: string;
  q?: string;
  query?: SearchQuery;
  channel?: string;
  destination?: string;
  cooldown_sec?: number;
  saved_search_id?: number;
};
