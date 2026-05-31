DROP TABLE IF EXISTS uv_remediation_recommendation;

DROP TABLE IF EXISTS uv_host_attack_path_score;
DROP TABLE IF EXISTS uv_host_relation;

DROP TABLE IF EXISTS uv_service_risk_snapshot;
DROP TABLE IF EXISTS uv_host_risk_snapshot;

DROP TABLE IF EXISTS uv_risk_policy;
DROP TABLE IF EXISTS uv_risk_protocol_prior;

DROP TABLE IF EXISTS uv_http_screenshot_job;
DROP TABLE IF EXISTS uv_http_screenshot;

DROP TRIGGER IF EXISTS uv_alert_event_trigger ON uv_alert_event;
DROP FUNCTION IF EXISTS uv_alert_event_notify();

DROP TRIGGER IF EXISTS uv_scan_delta_event_trigger ON uv_scan_delta_summary;
DROP FUNCTION IF EXISTS uv_scan_delta_notify();

DROP TRIGGER IF EXISTS uv_service_snapshot_event_trigger ON uv_service_snapshot;
DROP FUNCTION IF EXISTS uv_service_snapshot_notify();

DROP TRIGGER IF EXISTS uv_scan_event_trigger ON uv_scan;
DROP FUNCTION IF EXISTS uv_scan_event_notify();

DROP TRIGGER IF EXISTS uv_scan_pause_trigger ON uv_scan;
DROP FUNCTION IF EXISTS uv_scan_pause_notify();

DROP TRIGGER IF EXISTS uv_scan_cancel_trigger ON uv_scan;
DROP FUNCTION IF EXISTS uv_scan_cancel_notify();

DROP TABLE IF EXISTS uv_service_cve;
DROP TABLE IF EXISTS uv_cve_cpe;
DROP TABLE IF EXISTS uv_cve_sync_state;
DROP TABLE IF EXISTS uv_cve;
DROP TABLE IF EXISTS uv_cpe_product_map;
DROP TABLE IF EXISTS uv_service_match_state;

DROP TABLE IF EXISTS uv_audit_event;
DROP TABLE IF EXISTS uv_refresh_token;
DROP TABLE IF EXISTS uv_alert_event;
DROP TABLE IF EXISTS uv_alert_rule;
DROP TABLE IF EXISTS uv_saved_search;
DROP TABLE IF EXISTS uv_scan_delta_summary;
DROP TABLE IF EXISTS uv_service_change_event;
DROP SEQUENCE IF EXISTS uv_service_change_event_id_seq;
DROP TABLE IF EXISTS uv_service_snapshot;

ALTER TABLE IF EXISTS uv_scan DROP COLUMN IF EXISTS schedule_id;

DROP TABLE IF EXISTS uv_scan_schedule;
DROP TABLE IF EXISTS uv_scan;
DROP TABLE IF EXISTS uv_ct_observation;
DROP TABLE IF EXISTS uv_host_whois;
DROP TABLE IF EXISTS uv_dns_record;
DROP TABLE IF EXISTS uv_smtp_info;
DROP TABLE IF EXISTS uv_ssh_info;
DROP TABLE IF EXISTS uv_service_fingerprint;
DROP TABLE IF EXISTS uv_tls_finding;
DROP TABLE IF EXISTS uv_tls_chain_certificate;
DROP TABLE IF EXISTS uv_tls_certificate;
DROP TABLE IF EXISTS uv_http_security;
DROP TABLE IF EXISTS uv_http_response;
DROP TABLE IF EXISTS uv_service;
DROP TABLE IF EXISTS uv_host;
DROP TABLE IF EXISTS uv_user;

DROP FUNCTION IF EXISTS uv_to_tsvector_simple(TEXT);
DROP FUNCTION IF EXISTS uv_sans_to_text(TEXT[]);

DROP TYPE IF EXISTS UV_SCAN_STATUS;
DROP TYPE IF EXISTS UV_SERVICE_TRANSPORT;

DROP EXTENSION IF EXISTS pg_trgm;
