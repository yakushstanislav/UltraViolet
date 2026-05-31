-- Single consolidated schema (fresh installs).

CREATE EXTENSION pg_trgm;

CREATE TYPE UV_SERVICE_TRANSPORT AS ENUM ('TCP', 'UDP');

CREATE TYPE UV_SCAN_STATUS AS ENUM (
    'PENDING', 'RUNNING', 'DONE', 'FAILED', 'CANCELED', 'PAUSED'
);

-- Immutable wrappers required for GENERATED columns (PG rejects STABLE builtins).
CREATE OR REPLACE FUNCTION uv_sans_to_text(sans TEXT[])
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
RETURN array_to_string(sans, ' ');

CREATE OR REPLACE FUNCTION uv_to_tsvector_simple(txt TEXT)
RETURNS tsvector
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
RETURN to_tsvector('simple', coalesce(txt, ''));

CREATE TABLE uv_host
(
    id              BIGSERIAL PRIMARY KEY,
    ip              INET             NOT NULL UNIQUE,
    country_code    VARCHAR,
    country_name    VARCHAR,
    city            VARCHAR,
    latitude        DOUBLE PRECISION,
    longitude       DOUBLE PRECISION,
    asn             BIGINT,
    asn_org         VARCHAR,
    ptr_hostname    TEXT,
    first_seen      TIMESTAMP        NOT NULL,
    last_seen       TIMESTAMP        NOT NULL,
    risk_score      SMALLINT         NOT NULL DEFAULT 0,
    probability     NUMERIC(5, 4)    NOT NULL DEFAULT 0,
    impact          NUMERIC(5, 4)    NOT NULL DEFAULT 0.4,
    confidence      NUMERIC(4, 3)    NOT NULL DEFAULT 0,
    risk_factors    JSONB            NOT NULL DEFAULT '{}'::jsonb,
    risk_updated_at TIMESTAMP
);

ALTER TABLE uv_host SET (
    fillfactor = 70,
    autovacuum_vacuum_scale_factor = 0.005,
    autovacuum_analyze_scale_factor = 0.002
);

CREATE INDEX uv_host_country_idx       ON uv_host (country_code);
CREATE INDEX uv_host_asn_idx           ON uv_host (asn);
CREATE INDEX uv_host_risk_score_idx    ON uv_host (risk_score DESC);
CREATE INDEX uv_host_risk_recent_idx   ON uv_host (risk_score DESC, last_seen DESC, id DESC);
CREATE INDEX uv_host_probability_idx   ON uv_host (probability DESC);
CREATE INDEX uv_host_confidence_idx    ON uv_host (confidence  DESC);

-- Expression index that keeps the attack-path worker's shared_subnet pair
-- scan from devolving into a full cross-join. Postgres rewrites the
-- self-join equality into an index-only lookup on this expression.
CREATE INDEX uv_host_subnet24_idx
    ON uv_host (set_masklen(ip, 24))
    WHERE family(ip) = 4;

CREATE TABLE uv_user
(
    id            BIGSERIAL PRIMARY KEY,
    username      VARCHAR   NOT NULL UNIQUE,
    password_hash VARCHAR   NOT NULL,
    role          VARCHAR   NOT NULL,
    is_active     BOOLEAN   NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMP,
    created_at    TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP NOT NULL
);

CREATE INDEX uv_user_role_idx ON uv_user (role);

CREATE TABLE uv_scan
(
    id               BIGSERIAL PRIMARY KEY,
    name             VARCHAR,
    cidr             VARCHAR,
    country          VARCHAR(2),
    ports            INTEGER[]      NOT NULL,
    ports_expr       JSONB,
    status           UV_SCAN_STATUS NOT NULL,
    mode             VARCHAR(16)    NOT NULL DEFAULT 'slow',
    slow_profile     VARCHAR(16)    NOT NULL DEFAULT 'stealth',
    target_strategy  VARCHAR(16)    NOT NULL DEFAULT 'sequential',
    host_limit       BIGINT,
    started_at       TIMESTAMP,
    finished_at      TIMESTAMP,
    error            TEXT,
    stats            JSONB,
    stats_updated_at TIMESTAMP,
    cancel_requested BOOLEAN        NOT NULL DEFAULT FALSE,
    pause_requested  BOOLEAN        NOT NULL DEFAULT FALSE,
    auto_resume      BOOLEAN        NOT NULL DEFAULT FALSE,
    progress_cursor  TEXT           NOT NULL DEFAULT '',
    created_at       TIMESTAMP      NOT NULL
);

CREATE INDEX uv_scan_status_idx ON uv_scan (status);

CREATE TABLE uv_service
(
    id            BIGSERIAL PRIMARY KEY,
    host_id       BIGINT               NOT NULL REFERENCES uv_host (id) ON DELETE CASCADE,
    port          INTEGER              NOT NULL,
    transport     UV_SERVICE_TRANSPORT NOT NULL,
    protocol      VARCHAR,
    banner        TEXT,
    banner_hash   VARCHAR,
    banner_tsv    TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple', coalesce(banner, ''))) STORED,
    last_seen     TIMESTAMP            NOT NULL,
    risk_score    SMALLINT             NOT NULL DEFAULT 0,
    probability   NUMERIC(5, 4)        NOT NULL DEFAULT 0,
    confidence    NUMERIC(4, 3)        NOT NULL DEFAULT 0,
    risk_factors  JSONB                NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (host_id, port, transport)
);

ALTER TABLE uv_service SET (
    fillfactor = 70,
    autovacuum_vacuum_scale_factor = 0.005,
    autovacuum_analyze_scale_factor = 0.002
);

CREATE INDEX uv_service_port_idx        ON uv_service (port);
CREATE INDEX uv_service_protocol_idx    ON uv_service (protocol);
CREATE INDEX uv_service_risk_score_idx  ON uv_service (risk_score DESC);
CREATE INDEX uv_service_probability_idx ON uv_service (probability DESC);
CREATE INDEX uv_service_banner_tsv_idx  ON uv_service USING GIN (banner_tsv);
CREATE INDEX uv_service_last_seen_brin_idx
    ON uv_service USING BRIN (last_seen)
    WITH (pages_per_range = 128);
CREATE INDEX uv_service_host_idx        ON uv_service (host_id);
CREATE INDEX uv_service_risk_seen_idx   ON uv_service (risk_score DESC, last_seen DESC, id DESC);
CREATE INDEX uv_service_banner_trgm_idx
    ON uv_service USING GIN (banner gin_trgm_ops)
    WHERE banner IS NOT NULL AND banner <> '';

CREATE TABLE uv_http_response
(
    service_id       BIGINT    PRIMARY KEY REFERENCES uv_service (id) ON DELETE CASCADE,
    status_code      INTEGER,
    server_header    VARCHAR,
    title            VARCHAR,
    headers          JSONB,
    body             TEXT,
    body_tsv         TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple', coalesce(body, ''))) STORED,
    favicon_hash     INT,
    technologies     TEXT[],
    redirect_url     VARCHAR,
    redirect_chain   JSONB,
    robots_txt       TEXT,
    security_txt     TEXT,
    body_sha256      TEXT,
    not_found_hash   TEXT,
    alt_svc_raw      TEXT,
    http3_supported  BOOLEAN   NOT NULL DEFAULT FALSE,
    captured_at      TIMESTAMP NOT NULL
);

ALTER TABLE uv_http_response ALTER COLUMN body SET STORAGE EXTENDED;

CREATE INDEX uv_http_response_tsv_idx ON uv_http_response USING GIN (body_tsv);
CREATE INDEX uv_http_response_trgm_idx
    ON uv_http_response USING GIN (body gin_trgm_ops)
    WHERE body IS NOT NULL AND body <> '';
CREATE INDEX uv_http_response_title_idx ON uv_http_response (title);
CREATE INDEX uv_http_response_body_sha256_idx
    ON uv_http_response (body_sha256)
    WHERE body_sha256 IS NOT NULL;
CREATE INDEX uv_http_response_not_found_hash_idx
    ON uv_http_response (not_found_hash)
    WHERE not_found_hash IS NOT NULL;

CREATE TABLE uv_http_security
(
    service_id                   BIGINT  PRIMARY KEY REFERENCES uv_service (id) ON DELETE CASCADE,
    hsts_max_age                 BIGINT,
    hsts_include_subdomains      BOOLEAN NOT NULL DEFAULT FALSE,
    hsts_preload                 BOOLEAN NOT NULL DEFAULT FALSE,
    csp_present                  BOOLEAN NOT NULL DEFAULT FALSE,
    csp_has_unsafe_inline        BOOLEAN NOT NULL DEFAULT FALSE,
    csp_has_unsafe_eval          BOOLEAN NOT NULL DEFAULT FALSE,
    x_frame_options              TEXT,
    x_content_type_options       TEXT,
    referrer_policy              TEXT,
    permissions_policy_present   BOOLEAN NOT NULL DEFAULT FALSE,
    cors_allow_origin            TEXT,
    cookie_secure_count          INT     NOT NULL DEFAULT 0,
    cookie_httponly_count        INT     NOT NULL DEFAULT 0,
    cookie_samesite_strict_count INT     NOT NULL DEFAULT 0,
    cookie_samesite_lax_count    INT     NOT NULL DEFAULT 0,
    cookie_samesite_none_count   INT     NOT NULL DEFAULT 0,
    captured_at                  TIMESTAMP NOT NULL
);

CREATE TABLE uv_tls_certificate
(
    service_id         BIGINT PRIMARY KEY REFERENCES uv_service (id) ON DELETE CASCADE,
    subject            VARCHAR,
    issuer             VARCHAR,
    fingerprint_sha256 VARCHAR,
    not_before         TIMESTAMP,
    not_after          TIMESTAMP,
    raw_pem            TEXT,
    sans               TEXT[],
    sans_text          TEXT GENERATED ALWAYS AS (uv_sans_to_text(sans)) STORED,
    jarm_fingerprint   VARCHAR,
    tls_version        VARCHAR,
    cipher_suite       VARCHAR,
    ja3s_hash          VARCHAR,
    ja4s_hash          VARCHAR,
    security_grade     CHAR(1)
);

ALTER TABLE uv_tls_certificate ALTER COLUMN raw_pem SET STORAGE EXTENDED;

CREATE INDEX uv_tls_certificate_subject_trgm_idx
    ON uv_tls_certificate USING GIN (subject gin_trgm_ops);
CREATE INDEX uv_tls_certificate_sans_trgm_idx
    ON uv_tls_certificate USING GIN (sans_text gin_trgm_ops);

CREATE TABLE uv_tls_chain_certificate
(
    id                 BIGSERIAL PRIMARY KEY,
    service_id         BIGINT    NOT NULL REFERENCES uv_service (id) ON DELETE CASCADE,
    chain_position     INTEGER   NOT NULL,
    subject            VARCHAR,
    issuer             VARCHAR,
    fingerprint_sha256 VARCHAR,
    not_before         TIMESTAMP,
    not_after          TIMESTAMP,
    raw_pem            TEXT,
    sans               TEXT[],
    captured_at        TIMESTAMP NOT NULL,
    UNIQUE (service_id, chain_position)
);

CREATE INDEX uv_tls_chain_service_idx ON uv_tls_chain_certificate (service_id, chain_position);
CREATE INDEX uv_tls_chain_fp_idx ON uv_tls_chain_certificate (fingerprint_sha256);

CREATE TABLE uv_tls_finding
(
    id          BIGSERIAL PRIMARY KEY,
    service_id  BIGINT    NOT NULL REFERENCES uv_service (id) ON DELETE CASCADE,
    severity    TEXT      NOT NULL,
    code        TEXT      NOT NULL,
    detail      TEXT,
    captured_at TIMESTAMP NOT NULL
);

CREATE INDEX uv_tls_finding_service_idx  ON uv_tls_finding (service_id);
CREATE INDEX uv_tls_finding_severity_idx ON uv_tls_finding (severity);
CREATE INDEX uv_tls_finding_code_idx     ON uv_tls_finding (code);

CREATE TABLE uv_service_fingerprint
(
    id                BIGSERIAL PRIMARY KEY,
    service_id        BIGINT    NOT NULL REFERENCES uv_service (id) ON DELETE CASCADE,
    product           TEXT      NOT NULL,
    version           TEXT,
    edition           TEXT,
    cluster_role      TEXT,
    cluster_name      TEXT,
    auth_required     BOOLEAN,
    tls_required      BOOLEAN,
    anonymous         BOOLEAN   NOT NULL DEFAULT FALSE,
    raw_json          JSONB,
    fingerprint_hash  CHAR(64),
    source            TEXT      NOT NULL DEFAULT 'legacy',
    role              TEXT,
    captured_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX uv_service_fingerprint_unique_idx
    ON uv_service_fingerprint (service_id, product, COALESCE(version, ''), source);

CREATE INDEX uv_service_fingerprint_product_idx ON uv_service_fingerprint (product);
CREATE INDEX uv_service_fingerprint_product_version_idx
    ON uv_service_fingerprint (product, version);
CREATE INDEX uv_service_fingerprint_auth_idx ON uv_service_fingerprint (auth_required)
    WHERE auth_required IS NOT NULL;
CREATE INDEX uv_service_fingerprint_hash_idx ON uv_service_fingerprint (fingerprint_hash);

CREATE TABLE uv_service_match_state
(
    service_id       BIGINT PRIMARY KEY REFERENCES uv_service (id) ON DELETE CASCADE,
    fingerprint_hash CHAR(64) NOT NULL,
    matched_at       TIMESTAMPTZ NOT NULL
);

CREATE TABLE uv_ssh_info
(
    service_id           BIGINT PRIMARY KEY REFERENCES uv_service (id) ON DELETE CASCADE,
    server_version       VARCHAR,
    host_key_type        VARCHAR,
    host_key_fingerprint VARCHAR,
    kex_algorithms       TEXT[],
    host_key_algorithms  TEXT[],
    captured_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX uv_ssh_info_server_version_trgm_idx
    ON uv_ssh_info USING GIN (server_version gin_trgm_ops);
CREATE INDEX uv_ssh_info_host_key_fp_idx ON uv_ssh_info (host_key_fingerprint);

CREATE TABLE uv_smtp_info
(
    service_id       BIGINT PRIMARY KEY REFERENCES uv_service (id) ON DELETE CASCADE,
    banner           VARCHAR,
    capabilities     TEXT[],
    starttls         BOOLEAN   NOT NULL DEFAULT FALSE,
    auth_methods     TEXT[],
    max_message_size BIGINT,
    captured_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX uv_smtp_info_banner_trgm_idx ON uv_smtp_info USING GIN (banner gin_trgm_ops);

CREATE TABLE uv_dns_record
(
    id                BIGSERIAL PRIMARY KEY,
    host_id           BIGINT    NOT NULL REFERENCES uv_host (id) ON DELETE CASCADE,
    record_type       TEXT      NOT NULL,
    name              TEXT      NOT NULL,
    value             TEXT      NOT NULL,
    source            TEXT      NOT NULL DEFAULT 'ptr',
    forward_confirmed BOOLEAN   NOT NULL DEFAULT FALSE,
    captured_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    first_seen        TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE (host_id, record_type, value)
);

CREATE INDEX uv_dns_record_host_idx ON uv_dns_record (host_id);
CREATE INDEX uv_dns_record_name_trgm_idx ON uv_dns_record USING GIN (name gin_trgm_ops);
CREATE INDEX uv_dns_record_value_trgm_idx ON uv_dns_record USING GIN (value gin_trgm_ops);

CREATE TABLE uv_host_whois
(
    host_id       BIGINT PRIMARY KEY REFERENCES uv_host (id) ON DELETE CASCADE,
    network_name  VARCHAR,
    network_range VARCHAR,
    country       VARCHAR,
    abuse_email   VARCHAR,
    organization  VARCHAR,
    rdap_source   VARCHAR,
    raw_response  JSONB,
    captured_at   TIMESTAMP NOT NULL
);

CREATE TABLE uv_ct_observation
(
    id          BIGSERIAL PRIMARY KEY,
    host_id     BIGINT REFERENCES uv_host (id) ON DELETE CASCADE,
    common_name VARCHAR,
    san         VARCHAR,
    issuer      VARCHAR,
    not_before  TIMESTAMP,
    not_after   TIMESTAMP,
    serial      VARCHAR,
    log_source  VARCHAR,
    captured_at TIMESTAMP NOT NULL,
    UNIQUE (host_id, serial)
);

CREATE INDEX uv_ct_observation_host_idx ON uv_ct_observation (host_id);
CREATE INDEX uv_ct_observation_san_idx ON uv_ct_observation (san);

CREATE TABLE uv_saved_search
(
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT REFERENCES uv_user (id) ON DELETE SET NULL,
    name        VARCHAR   NOT NULL,
    query       JSONB     NOT NULL,
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL,
    last_run_at TIMESTAMP
);

CREATE SEQUENCE uv_service_change_event_id_seq;

CREATE TABLE uv_service_snapshot
(
    scan_id     BIGINT               NOT NULL,
    host_id     BIGINT               NOT NULL,
    service_id  BIGINT               NOT NULL,
    ip          INET                 NOT NULL,
    port        INTEGER              NOT NULL,
    transport   UV_SERVICE_TRANSPORT NOT NULL,
    protocol    VARCHAR,
    banner_hash VARCHAR,
    title       VARCHAR,
    status_code INTEGER,
    tls_fp      VARCHAR,
    created_at  TIMESTAMP            NOT NULL,
    PRIMARY KEY (scan_id, service_id)
) PARTITION BY RANGE (scan_id);

ALTER TABLE uv_service_snapshot
    ADD CONSTRAINT fk_snapshot_scan
    FOREIGN KEY (scan_id) REFERENCES uv_scan (id) ON DELETE CASCADE;

ALTER TABLE uv_service_snapshot
    ADD CONSTRAINT fk_snapshot_host
    FOREIGN KEY (host_id) REFERENCES uv_host (id) ON DELETE CASCADE;

ALTER TABLE uv_service_snapshot
    ADD CONSTRAINT fk_snapshot_service
    FOREIGN KEY (service_id) REFERENCES uv_service (id) ON DELETE CASCADE;

CREATE TABLE uv_service_snapshot_default
    PARTITION OF uv_service_snapshot DEFAULT;

CREATE INDEX uv_service_snapshot_host_idx
    ON uv_service_snapshot (host_id, created_at DESC);

CREATE TABLE uv_service_change_event
(
    id               BIGINT    NOT NULL DEFAULT nextval('uv_service_change_event_id_seq'),
    scan_id          BIGINT    NOT NULL,
    host_id          BIGINT    NOT NULL,
    service_id       BIGINT,
    previous_scan_id BIGINT,
    change_type      VARCHAR   NOT NULL,
    details          JSONB     NOT NULL,
    created_at       TIMESTAMP NOT NULL,
    PRIMARY KEY (scan_id, id)
) PARTITION BY RANGE (scan_id);

ALTER SEQUENCE uv_service_change_event_id_seq
    OWNED BY uv_service_change_event.id;

ALTER TABLE uv_service_change_event
    ADD CONSTRAINT fk_change_event_scan
    FOREIGN KEY (scan_id) REFERENCES uv_scan (id) ON DELETE CASCADE;

ALTER TABLE uv_service_change_event
    ADD CONSTRAINT fk_change_event_host
    FOREIGN KEY (host_id) REFERENCES uv_host (id) ON DELETE CASCADE;

CREATE TABLE uv_service_change_event_default
    PARTITION OF uv_service_change_event DEFAULT;

CREATE INDEX uv_service_change_scan_idx
    ON uv_service_change_event (scan_id, id DESC);

CREATE INDEX uv_service_change_host_idx
    ON uv_service_change_event (host_id, id DESC);

CREATE INDEX uv_service_change_event_created_idx
    ON uv_service_change_event (created_at);

CREATE TABLE uv_scan_delta_summary
(
    scan_id              BIGINT PRIMARY KEY REFERENCES uv_scan (id) ON DELETE CASCADE,
    previous_scan_id     BIGINT,
    new_services         INTEGER NOT NULL DEFAULT 0,
    disappeared_services INTEGER NOT NULL DEFAULT 0,
    changed_services     INTEGER NOT NULL DEFAULT 0,
    created_at           TIMESTAMP NOT NULL
);

CREATE TABLE uv_scan_schedule
(
    id               BIGSERIAL PRIMARY KEY,
    name             VARCHAR(256)  NOT NULL,
    enabled          BOOLEAN       NOT NULL DEFAULT TRUE,
    interval_seconds INTEGER       NOT NULL CHECK (interval_seconds >= 300),
    target           VARCHAR(253),
    scan_subnet      BOOLEAN       NOT NULL DEFAULT FALSE,
    mode             VARCHAR(32)   NOT NULL,
    slow_profile     VARCHAR(32)   NOT NULL,
    target_strategy  VARCHAR(32)   NOT NULL,
    host_limit       BIGINT,
    ports_expr       JSONB         NOT NULL,
    last_run_at      TIMESTAMPTZ,
    last_scan_id     BIGINT REFERENCES uv_scan (id) ON DELETE SET NULL,
    next_run_at      TIMESTAMPTZ   NOT NULL,
    created_by       BIGINT REFERENCES uv_user (id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX uv_scan_schedule_due_idx ON uv_scan_schedule (next_run_at) WHERE enabled;

ALTER TABLE uv_scan
    ADD COLUMN schedule_id BIGINT REFERENCES uv_scan_schedule (id) ON DELETE SET NULL;

CREATE INDEX uv_scan_schedule_id_idx ON uv_scan (schedule_id) WHERE schedule_id IS NOT NULL;

CREATE TABLE uv_alert_rule
(
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT REFERENCES uv_user (id) ON DELETE SET NULL,
    name            VARCHAR NOT NULL,
    saved_search_id BIGINT REFERENCES uv_saved_search (id) ON DELETE SET NULL,
    query           JSONB   NOT NULL,
    channel         VARCHAR NOT NULL DEFAULT 'log',
    destination     VARCHAR NOT NULL DEFAULT '',
    cooldown_sec    INTEGER NOT NULL DEFAULT 300,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    last_fired_at   TIMESTAMP,
    created_at      TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP NOT NULL
);

CREATE TABLE uv_alert_event
(
    id            BIGSERIAL PRIMARY KEY,
    alert_rule_id BIGINT NOT NULL REFERENCES uv_alert_rule (id) ON DELETE CASCADE,
    hits_count    INTEGER NOT NULL,
    payload       JSONB   NOT NULL,
    created_at    TIMESTAMP NOT NULL
);

CREATE TABLE uv_refresh_token
(
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT    NOT NULL REFERENCES uv_user (id) ON DELETE CASCADE,
    token_hash VARCHAR   NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX uv_refresh_token_user_idx ON uv_refresh_token (user_id);
CREATE INDEX uv_refresh_token_expiry_idx ON uv_refresh_token (expires_at);

CREATE TABLE uv_audit_event
(
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT REFERENCES uv_user (id) ON DELETE SET NULL,
    actor_role  VARCHAR,
    actor_ip    VARCHAR,
    method      VARCHAR NOT NULL,
    path        VARCHAR NOT NULL,
    status_code INTEGER NOT NULL,
    resource_id VARCHAR,
    user_agent  VARCHAR,
    created_at  TIMESTAMP NOT NULL
);

CREATE INDEX uv_audit_event_user_idx ON uv_audit_event (user_id, id DESC);
CREATE INDEX uv_audit_event_path_idx ON uv_audit_event (path, id DESC);

CREATE TABLE uv_cve
(
    id                      TEXT PRIMARY KEY,
    source                  TEXT      NOT NULL DEFAULT 'nvd',
    summary                 TEXT,
    summary_tsv             TSVECTOR GENERATED ALWAYS AS (uv_to_tsvector_simple(summary)) STORED,
    cvss_v3_score           NUMERIC(3, 1),
    cvss_v3_severity        VARCHAR(16),
    cvss_v3_vector          VARCHAR,
    cvss_v31_score          NUMERIC(3, 1),
    cvss_v31_severity       TEXT,
    cvss_v31_vector         TEXT,
    cvss_v40_score          NUMERIC(3, 1),
    cvss_v40_severity       TEXT,
    cvss_v40_vector         TEXT,
    published_at            TIMESTAMP,
    last_modified_at        TIMESTAMP,
    refs                    JSONB     NOT NULL DEFAULT '[]'::jsonb,
    raw_json                JSONB,
    kev_added_at            TIMESTAMP,
    kev_due_date            TIMESTAMP,
    kev_known_ransomware    BOOLEAN,
    epss_score              NUMERIC(6, 5),
    epss_percentile         NUMERIC(6, 5),
    epss_scored_at          TIMESTAMP,
    ingested_at             TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX uv_cve_last_modified_idx ON uv_cve (last_modified_at DESC);
CREATE INDEX uv_cve_severity_idx ON uv_cve (cvss_v3_severity);
CREATE INDEX uv_cve_score_idx ON uv_cve (cvss_v3_score DESC);
CREATE INDEX uv_cve_summary_tsv_idx ON uv_cve USING GIN (summary_tsv);
CREATE INDEX uv_cve_id_trgm_idx ON uv_cve USING GIN (id gin_trgm_ops);
CREATE INDEX uv_cve_kev_idx ON uv_cve (kev_added_at) WHERE kev_added_at IS NOT NULL;
CREATE INDEX uv_cve_epss_idx ON uv_cve (epss_score DESC NULLS LAST);

CREATE TABLE uv_cve_cpe
(
    id                       BIGSERIAL PRIMARY KEY,
    cve_id                   TEXT NOT NULL REFERENCES uv_cve (id) ON DELETE CASCADE,
    vendor                   TEXT NOT NULL,
    product                  TEXT NOT NULL,
    version_start_including  TEXT,
    version_start_excluding  TEXT,
    version_end_including    TEXT,
    version_end_excluding    TEXT,
    exact_version            TEXT,
    raw_cpe                  TEXT NOT NULL,
    vulnerable               BOOLEAN NOT NULL DEFAULT TRUE,
    target_sw                TEXT,
    target_hw                TEXT,
    negate                   BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX uv_cve_cpe_vendor_product_idx ON uv_cve_cpe (vendor, product);
CREATE INDEX uv_cve_cpe_cve_idx ON uv_cve_cpe (cve_id);
CREATE INDEX uv_cve_cpe_target_sw_idx ON uv_cve_cpe (target_sw) WHERE target_sw IS NOT NULL;
CREATE INDEX uv_cve_cpe_catchall_idx
    ON uv_cve_cpe (vendor, product)
    WHERE vulnerable = TRUE
      AND exact_version IS NULL
      AND version_start_including IS NULL
      AND version_start_excluding IS NULL
      AND version_end_including IS NULL
      AND version_end_excluding IS NULL;

CREATE TABLE uv_service_cve
(
    service_id      BIGINT        NOT NULL REFERENCES uv_service (id) ON DELETE CASCADE,
    cve_id          TEXT          NOT NULL REFERENCES uv_cve (id) ON DELETE CASCADE,
    matched_version TEXT,
    severity        VARCHAR(16),
    cvss_score      NUMERIC(3, 1),
    confidence      SMALLINT      NOT NULL DEFAULT 60,
    matched_at      TIMESTAMP     NOT NULL,
    kev_added_at    TIMESTAMP,
    epss_score      NUMERIC(6, 5),
    PRIMARY KEY (service_id, cve_id)
);

CREATE INDEX uv_service_cve_cve_idx ON uv_service_cve (cve_id);
CREATE INDEX uv_service_cve_severity_idx ON uv_service_cve (severity, matched_at DESC);
CREATE INDEX uv_service_cve_score_idx ON uv_service_cve (cvss_score DESC);
CREATE INDEX uv_service_cve_confidence_idx ON uv_service_cve (confidence DESC, severity);
CREATE INDEX uv_service_cve_kev_idx ON uv_service_cve (service_id) WHERE kev_added_at IS NOT NULL;
CREATE INDEX uv_service_cve_epss_idx ON uv_service_cve (epss_score DESC NULLS LAST);

CREATE TABLE uv_cve_sync_state
(
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_mod_start  TIMESTAMP,
    bootstrapped_at TIMESTAMP,
    entries_total   INTEGER,
    entries_done    INTEGER,
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

INSERT INTO uv_cve_sync_state (id) VALUES (1) ON CONFLICT DO NOTHING;

CREATE TABLE uv_cpe_product_map
(
    product_key TEXT NOT NULL,
    vendor      TEXT NOT NULL,
    product     TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT 'builtin',
    PRIMARY KEY (product_key, vendor, product)
);

CREATE INDEX uv_cpe_product_map_product_key_idx ON uv_cpe_product_map (product_key);

-- Seed rows: go run ./cmd/cpemap-seed >> deploy/migrations/1_initial_schema.up.sql
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('1c-bitrix', '1c-bitrix', 'bitrix_site_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('1c-bitrix', 'bitrix', 'bitrix24', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_800xa', 'abb', '800xa', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_800xa', 'abb', 'system_800xa', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_ev_charger', 'abb', 'terra_ac_wallbox_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_ev_charger', 'abb', 'terra_dc_charger_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_plc', 'abb', 'ac500', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_plc', 'abb', 'ac500-eco', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_plc', 'abb', 'rtu500', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_robotware', 'abb', 'irc5', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('abb_robotware', 'abb', 'robotware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('acarsdec', 'thierry_leconte', 'acarsdec', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('acarsdec', 'tlevecque', 'acarsdec', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('adguard_home', 'adguard', 'adguard_home', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('adguard_home', 'adguardteam', 'adguardhome', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('advantech_iot', 'advantech', 'edgelink', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('advantech_iot', 'advantech', 'uno-2271g_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('advantech_iot', 'advantech', 'wise-paas', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('aeotec_zstick', 'aeon_labs', 'z-stick', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('aeotec_zstick', 'aeotec', 'z-stick_7', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('agleader_incommand', 'ag-leader', 'incommand_800_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('agleader_incommand', 'ag_leader', 'incommand_1200_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('airflow', 'apache', 'airflow', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ais_receiver', 'aishub', 'ais', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ais_receiver', 'itu', 'ais', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('alfen_eve', 'alfen', 'eve_double_pro-line', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('alfen_eve', 'alfen', 'eve_single_pro-line', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('alfen_eve', 'alfen', 'nf-firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amazon_echo', 'amazon', 'alexa', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amazon_echo', 'amazon', 'echo_dot', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amazon_echo', 'amazon', 'echo_show', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amcrest_camera', 'amcrest', 'ip2m-841_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amcrest_camera', 'amcrest', 'ip_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amqp', 'pivotal_software', 'rabbitmq', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amqp', 'rabbitmq', 'rabbitmq', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amx_netlinx', 'amx', 'netlinx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('amx_netlinx', 'harman', 'amx_netlinx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('andersen_a2', 'andersen-ev', 'a2_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apache', 'apache', 'http_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apache-httpd', 'apache', 'http_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apollo_fire', 'apollo', 'discovery_facp_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apollo_fire', 'apollo-fire-detectors', 'discovery', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apple_filing_protocol', 'apple', 'macos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apple_filing_protocol', 'netatalk', 'netatalk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apple_homekit_bridge', 'apple', 'homekit', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apple_homekit_bridge', 'homebridge', 'homebridge', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apple_tv', 'apple', 'airplay', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apple_tv', 'apple', 'apple_tv', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apple_tv', 'apple', 'apple_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('apple_tv', 'apple', 'tvos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('aqara_hub', 'aqara', 'hub_e1_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('aqara_hub', 'aqara', 'hub_m2_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('aqara_hub', 'lumi', 'aqara_hub', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('arcserve_udp', 'arcserve', 'udp', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('arcserve_udp', 'arcserve', 'unified_data_protection', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('argo_workflows', 'argoproj', 'argo_workflows', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('argo_workflows', 'linuxfoundation', 'argo', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('argocd', 'argoproj', 'argo_cd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('argocd', 'linuxfoundation', 'argo_cd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('arlo_pro', 'arlo', 'pro_3_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('arlo_pro', 'arlo_technologies', 'base_station_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('arlo_pro', 'netgear', 'arlo', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('asp_net', 'microsoft', '.net', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('asp_net', 'microsoft', '.net_framework', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('asp_net', 'microsoft', 'asp.net_core', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('asterisk_pbx', 'asterisk', 'asterisk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('asterisk_pbx', 'digium', 'asterisk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('august_lock', 'august', 'smart_lock', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('august_lock', 'august_home', 'wi-fi_smart_lock_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('automatedlogic_bacnet', 'automatedlogic', 'webctrl', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('autronica_fire', 'autronica', 'autroprime', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('autronica_fire', 'autronica', 'autrosafe', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('avaya_aura', 'avaya', 'aura_communication_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('avaya_aura', 'avaya', 'aura_session_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('avaya_aura', 'avaya', 'session_border_controller_for_enterprise', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('avigilon_acc', 'avigilon', 'acc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('avigilon_acc', 'avigilon', 'control_center', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('axis_a1001', 'axis', 'a1001_network_door_controller_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('axis_a1001', 'axis', 'a1601_network_door_controller_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('axis_camera', 'axis', 'axis_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('axis_camera', 'axis', 'axis_os', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('axis_camera', 'axis', 'communications_axis_os', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('axis_entry_manager', 'axis', 'entry_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bacnet', 'ashrae', 'bacnet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bacnet_secure', 'ashrae', 'bacnet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bacnet_secure', 'bacnet', 'bacnet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bacula', 'bacula', 'bacula', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bacula', 'kern_sibbald', 'bacula', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('badger_meter', 'badger-meter', 'orion_se', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('badger_meter', 'badgermeter', 'beacon_ama', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bareos', 'bareos', 'bareos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bareos', 'bareos-gmbh', 'bareos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bcoin_node', 'bcoin', 'bcoin', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bcoin_node', 'bcoin-org', 'bcoin', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('belkin_wemo', 'belkin', 'wemo_insight_switch_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('belkin_wemo', 'belkin', 'wemo_smart_plug_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('belkin_wemo', 'belkin', 'wemo_switch_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('belkin_wemo', 'linksys', 'wemo_link_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitbucket', 'atlassian', 'bitbucket', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitbucket', 'atlassian', 'bitbucket_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitcoin_core', 'bitcoin', 'bitcoin', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitcoin_core', 'bitcoin', 'bitcoin_core', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitcoin_core', 'bitcoincore', 'bitcoin_core', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitcoin_knots', 'bitcoinknots', 'bitcoin_knots', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitcoin_knots', 'luke-jr', 'bitcoin_knots', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitrix', '1c-bitrix', 'bitrix_site_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bitrix', 'bitrix', 'bitrix24', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bolid_orion', 'bolid', 'orion_pro', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bolid_orion', 'bolid', 's2000m', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bosch_avenar', 'bosch', 'avenar_panel_2000_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bosch_avenar', 'bosch', 'avenar_panel_8000_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bosch_avenar', 'bosch', 'fpa-1200', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bosch_bvms', 'bosch', 'bvms', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bosch_bvms', 'bosch', 'video_management_system', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bose_soundtouch', 'bose', 'soundtouch_10', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bose_soundtouch', 'bose', 'soundtouch_30_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('brother_printer', 'brother', 'printer_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bsh_home_connect', 'bosch', 'home_connect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bsh_home_connect', 'bsh-group', 'home_connect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('bsh_home_connect', 'bsh_hausgeraete', 'home_connect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('btcd_node', 'btcsuite', 'btcd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('caddy', 'caddyserver', 'caddy', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('canon_printer', 'canon', 'imagerunner_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('canon_printer', 'canon', 'printer_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('casambi_gateway', 'casambi', 'evolution_gateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('casambi_gateway', 'casambi', 'key', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cassandra', 'apache', 'cassandra', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ceph_mon', 'ceph', 'ceph', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ceph_mon', 'redhat', 'ceph_storage', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cerner_millennium', 'cerner', 'millennium', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cerner_millennium', 'oracle', 'cerner_millennium', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('chargepoint_home_flex', 'chargepoint', 'home_flex_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cilium_agent', 'cilium', 'cilium', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cilium_agent', 'isovalent', 'cilium', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('circontrol_raption', 'circontrol', 'raption_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_asa', 'cisco', 'adaptive_security_appliance', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_asa', 'cisco', 'asa_5500-x', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_cucm', 'cisco', 'unified_cm', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_cucm', 'cisco', 'unified_communications_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_ios', 'cisco', 'ios', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_ios', 'cisco', 'ios_xe', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_nxos', 'cisco', 'nx-os', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_sip_gateway', 'cisco', 'ios', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cisco_sip_gateway', 'cisco', 'unified_communications_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('clickhouse', 'clickhouse', 'clickhouse', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('clickhouse', 'yandex', 'clickhouse', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cloudflared', 'cloudflare', 'cloudflare_tunnel', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cloudflared', 'cloudflare', 'cloudflared', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('coap', 'californium', 'californium', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('coap', 'eclipse', 'californium', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('coap', 'ietf', 'coap', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cockroach', 'cockroach_labs', 'cockroachdb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cockroach', 'cockroachlabs', 'cockroachdb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('codesys_v3', '3s-smart_software_solutions', 'codesys', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('codesys_v3', 'codesys', 'control_for_iot2000_sl', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('codesys_v3', 'codesys', 'control_runtime_system_toolkit', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('codesys_v3', 'codesys', 'control_v3', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('codesys_v3', 'codesys', 'gateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cohesity_dataplatform', 'cohesity', 'data_cloud', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cohesity_dataplatform', 'cohesity', 'dataplatform', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('commvault_backup', 'commvault', 'backup_&_recovery', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('commvault_backup', 'commvault', 'commcell', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('commvault_backup', 'commvault', 'commvault', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('compleo_csms', 'compleo', 'ebox_charging_station', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('compleo_csms', 'compleo', 'etrel_inch_pro_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('concourse_ci', 'concourse-ci', 'concourse', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('concourse_ci', 'pivotal_software', 'concourse', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('confluence', 'atlassian', 'confluence', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('confluence', 'atlassian', 'confluence_data_center', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('confluence', 'atlassian', 'confluence_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('consul', 'hashicorp', 'consul', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('containerd', 'linuxfoundation', 'containerd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('courier', 'courier-mta', 'courier-mta', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('crestron_control', 'crestron', 'control_system', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('crestron_control', 'crestron', 'tsw_panel_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('crestron_control', 'crestron_electronics', 'control_system_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('crowd', 'atlassian', 'crowd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cubic_nextfare', 'cubic', 'nextfare', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cubic_nextfare', 'cubic_transportation_systems', 'nextfare', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cups', 'apple', 'cups', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cups', 'cups', 'cups', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cups', 'openprinting', 'cups', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cups', 'openprinting', 'cups-browsed', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('cups', 'openprinting', 'cups-filters', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dahua_camera', 'dahua', 'ip_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dahua_camera', 'dahuasecurity', 'ip_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dahua_camera', 'dahuasecurity', 'nvr_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dali2_iot', 'lunatone', 'dali2_iot', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dali2_iot', 'lunatone', 'dali_cockpit', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('datadog_agent', 'datadog', 'agent', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('datadog_agent', 'datadog', 'datadog_agent', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('datadog_agent', 'datadoghq', 'agent', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dcm4chee', 'dcm4che', 'dcm4che', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dcm4chee', 'dcm4che', 'dcm4chee', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dcmtk', 'dcmtk', 'dcmtk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dcmtk', 'offis', 'dcmtk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('deconz_conbee', 'dresden-elektronik', 'deconz', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('deconz_conbee', 'dresden_elektronik', 'conbee_ii', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('delaval_vms', 'delaval', 'delpro', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('delaval_vms', 'delaval', 'vms_v300_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dell_edge_gateway', 'dell', 'edge_gateway_3000', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dell_edge_gateway', 'dell', 'edge_gateway_5100', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dell_edge_gateway', 'dell', 'edge_gateway_5200', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('delta_controls_bacnet', 'deltacontrols', 'entelitouch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('delta_dc', 'delta', 'dc_fast_charger_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('delta_dc', 'delta_energy', 'ufc_200_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('denon_heos', 'denon', 'heos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('denon_heos', 'denon', 'heos_drive_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('denon_heos', 'soundunited', 'heos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('denso_robotics', 'denso', 'rc8', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('denso_robotics', 'denso', 'robotics', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dicom', 'dicom', 'dicom', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dicom', 'nema', 'dicom', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('discourse', 'discourse', 'discourse', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dlms_cosem', 'dlms', 'cosem', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dlms_cosem', 'iec', '62056', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dnp3', 'automatak', 'dnp3', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dnp3', 'automatak', 'opendnp3', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dnp3', 'trianglemicroworks', 'scada_data_gateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dns', 'isc', 'bind', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dns_over_https', 'cloudflare', 'cloudflare_dns', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dns_over_https', 'ietf', 'rfc8484', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dns_over_tls', 'ietf', 'rfc7858', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dns_over_tls', 'isc', 'bind', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('docker', 'docker', 'docker', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('docker', 'docker', 'engine', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dotnet', 'microsoft', '.net', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dotnet', 'microsoft', '.net_framework', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('drone_ci', 'drone', 'drone', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('drone_ci', 'harness', 'drone', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('druid', 'apache', 'druid', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('drupal', 'drupal', 'drupal', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dump1090', 'antirez', 'dump1090', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dump1090', 'flightaware', 'dump1090-fa', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dump1090', 'wiedehopf', 'readsb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dynalite_dynet', 'philips', 'dynalite', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('dynalite_dynet', 'signify', 'dynalite', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('easee_home', 'easee', 'equalizer', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('easee_home', 'easee', 'home_charger_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('eaton_xcomfort', 'eaton', 'intelligent_power_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('eaton_xcomfort', 'eaton', 'xcomfort_smart_home_controller', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('econolite_asc3', 'econolite', 'asc_3', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('econolite_asc3', 'econolite', 'cobalt', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('econolite_asc3', 'econolite', 'eos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('econolite_cobalt', 'econolite', 'cobalt', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('edgex_foundry', 'edgexfoundry', 'core-data', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('edgex_foundry', 'edgexfoundry', 'edgex-go', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('edgex_foundry', 'linuxfoundation', 'edgex_foundry', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('edwards_est3', 'carrier', 'est3', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('edwards_est3', 'edwards', 'est3_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('edwards_est3', 'edwards', 'est3x_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('efacec_qc', 'efacec', 'qc45_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('elasticsearch', 'elastic', 'elasticsearch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('elasticsearch', 'elasticsearch', 'elasticsearch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('electrolux_appliances', 'electrolux', 'aeg_my_aeg_kitchen', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('electrolux_appliances', 'electrolux', 'my_electrolux', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('electrolux_appliances', 'electrolux', 'smart_appliance_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('emc_isilon', 'dell', 'isilon_onefs', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('emc_isilon', 'emc', 'isilon_onefs', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('emerson_deltav', 'emerson', 'deltav', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('emerson_deltav', 'emersonprocess', 'deltav', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('emerson_ovation', 'emerson', 'ovation', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('emerson_ovation', 'westinghouse', 'ovation', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('endress_hauser', 'endress-hauser', 'fieldcare', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('endress_hauser', 'endress-hauser', 'memograph_m_rsg45', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('enelx_juicebox', 'enelx', 'juicebox_40_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('enelx_juicebox', 'enelx', 'juicepump_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('envoy', 'cncf', 'envoy', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('envoy', 'envoyproxy', 'envoy', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('epic_chronicles', 'epic', 'chronicles', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('epic_chronicles', 'epic_systems', 'chronicles', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('epson_printer', 'epson', 'epson_printer_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('esphome', 'esphome', 'esphome', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('esxi', 'vmware', 'esxi', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('etcd', 'coreos', 'etcd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('etcd', 'etcd', 'etcd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_erigon', 'erigon', 'erigon', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_erigon', 'ledgerwatch', 'erigon', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_geth', 'ethereum', 'geth', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_geth', 'ethereum', 'go-ethereum', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_geth', 'go-ethereum', 'go-ethereum', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_lighthouse', 'lighthouse', 'lighthouse', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_lighthouse', 'sigp', 'lighthouse', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_nethermind', 'nethermind', 'nethermind', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_nethermind', 'nethermindeth', 'nethermind', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_openethereum', 'openethereum', 'openethereum', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_openethereum', 'parity_technologies', 'parity-ethereum', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_prysm', 'prysm', 'prysm', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethereum_prysm', 'prysmaticlabs', 'prysm', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethernet_ip', 'odva', 'common_industrial_protocol', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ethernet_ip', 'rockwellautomation', 'ethernetip', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('eufy_security', 'anker', 'eufy_security_camera', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('eufy_security', 'eufy', 'security_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ev_manager', 'ev_manager', 'ev_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('evbox_elvi', 'engie', 'evbox_elvi', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('evbox_elvi', 'evbox', 'elvi_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('evbox_elvi', 'evbox', 'liviqo', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('evolve_charge', 'evolve-charge', 'firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('exchange', 'microsoft', 'exchange_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('exim', 'exim', 'exim', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('express', 'expressjs', 'express', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('express', 'openjsf', 'express', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('fanuc_focas', 'fanuc', 'cnc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('fanuc_focas', 'fanuc', 'focas', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('flink', 'apache', 'flink', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('fortinet', 'fortinet', 'fortigate', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('fortinet', 'fortinet', 'fortios', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('foscam_camera', 'foscam', 'fi8918w_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('foscam_camera', 'foscam', 'ip_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('freepbx', 'freepbx', 'freepbx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('freepbx', 'sangoma', 'freepbx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('freeswitch', 'freeswitch', 'freeswitch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('freeswitch', 'signalwire', 'freeswitch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('fronius_solar', 'fronius', 'datamanager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('fronius_solar', 'fronius', 'solar.web', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ftp', 'proftpd', 'proftpd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ftp', 'vsftpd', 'vsftpd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('galcon_irrigation', 'galcon', '8056', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('galcon_irrigation', 'galcon', 'wifi_controller', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gallagher_command', 'gallagher', 'command_centre', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('garo_gnm', 'garo', 'entity_pro', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('garo_gnm', 'garo', 'gnm_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gea_dairy', 'gea', 'dairyplan_c21', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gea_dairy', 'gea-group', 'dairyplan_c21', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('genetec_security_center', 'genetec', 'security_center', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('genetec_security_center', 'genetec', 'synergis_softwire', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('genetec_synergis', 'genetec', 'synergis_master_controller', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('genetec_synergis', 'genetec', 'synergis_softwire', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gent_fire', 'gent', 'vigilon', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gent_fire', 'honeywell', 'gent_vigilon', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ghost', 'ghost', 'ghost', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gitea', 'gitea', 'gitea', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('github_enterprise', 'github', 'enterprise', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('github_enterprise', 'github', 'enterprise_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gitlab', 'gitlab', 'gitlab', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('glassfish', 'eclipse', 'glassfish', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('glassfish', 'oracle', 'glassfish_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('globalprotect', 'paloaltonetworks', 'globalprotect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('globalprotect', 'paloaltonetworks', 'pan-os', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gluster_fs', 'gluster', 'glusterfs', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gluster_fs', 'redhat', 'gluster_storage', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gnu_radio', 'gnu', 'gnuradio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gnu_radio', 'gnuradio', 'gnu_radio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('go', 'golang', 'go', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gocd', 'gocd', 'gocd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gocd', 'thoughtworks', 'gocd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gogs', 'gogs', 'gogs', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('golang', 'golang', 'go', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('google_chromecast', 'google', 'android_tv', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('google_chromecast', 'google', 'android_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('google_chromecast', 'google', 'cast', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('google_chromecast', 'google', 'chromecast', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('google_chromecast', 'google', 'chromecast_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('google_nest_audio', 'google', 'nest_audio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('google_nest_audio', 'google', 'nest_hub_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('google_nest_audio', 'google', 'nest_mini', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('grafana', 'grafana', 'grafana', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('grafana_loki', 'grafana', 'loki', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('grafana_loki', 'grafanalabs', 'loki', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('grafana_tempo', 'grafana', 'tempo', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('grafana_tempo', 'grafanalabs', 'tempo', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('grandstream_phone', 'grandstream', 'gxp_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('grandstream_phone', 'grandstream', 'ht_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('grandstream_phone', 'grandstream', 'ucm_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('gunicorn', 'gunicorn', 'gunicorn', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hach_wims', 'hach', 'claros', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hach_wims', 'hach', 'wims', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hadoop', 'apache', 'hadoop', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('haier_hon', 'haier', 'hon', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('haier_hon', 'haier', 'hon_app', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('haier_hon', 'haier', 'smart_appliance_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('haproxy', 'haproxy', 'haproxy', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('harbor', 'linuxfoundation', 'harbor', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('harbor', 'vmware', 'harbor', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('helvar_imagine', 'helvar', 'imagine_910', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('helvar_imagine', 'helvar', 'imagine_router', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hiawatha', 'hiawatha-webserver', 'hiawatha', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_edge', 'hid', 'edge_evo', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_edge', 'hid', 'edge_evo_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_mercury', 'hid', 'mercury_lp1501', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_mercury', 'hid', 'mercury_lp1502_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_mercury', 'mercury_security', 'lp1502', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_mercury', 'mercury_security', 'lp4502', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_mercury', 'mercury_security', 'mr52', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_vertx', 'hid', 'vertx_evo_v1000_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hid_vertx', 'hid', 'vertx_evo_v2000_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hikvision_camera', 'hikvision', 'dvr_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hikvision_camera', 'hikvision', 'ip_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hikvision_camera', 'hikvision', 'nvr_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hisense_vidaa', 'hisense', 'smart_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hisense_vidaa', 'hisense', 'vidaa', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hisense_vidaa', 'hisense', 'vidaa_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hive', 'apache', 'hive', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hl7_mllp', 'hl7', 'hl7', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hl7_mllp', 'hl7', 'mllp', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hochiki_fire', 'hochiki', 'ekho', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hochiki_fire', 'hochiki', 'esp-r', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('home_assistant', 'home-assistant', 'home-assistant', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('home_assistant', 'home_assistant', 'home_assistant_core', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('homey_pro', 'athom', 'homey', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('homey_pro', 'athom', 'homey_pro', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('honeywell_bacnet', 'honeywell', 'experion_pks', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('honeywell_bacnet', 'honeywell', 'ip-ak2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('honeywell_bacnet', 'honeywell', 'xls80e_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('honeywell_prowatch', 'honeywell', 'pro-watch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('honeywell_prowatch', 'honeywell', 'prowatch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hp_printer', 'hp', 'color_laserjet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hp_printer', 'hp', 'deskjet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hp_printer', 'hp', 'laserjet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hp_printer', 'hp', 'officejet_pro', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hue_bridge', 'philips', 'hue_bridge_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hue_bridge', 'signify', 'hue_bridge', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hunter_hydrawise', 'hunter', 'hydrawise_cloud', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hunter_hydrawise', 'hunterindustries', 'hydrawise', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hyperledger_besu', 'consensys', 'besu', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('hyperledger_besu', 'hyperledger', 'besu', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iconics_genesis', 'iconics', 'genesis64', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iconics_genesis', 'mitsubishielectric', 'iconics_genesis64', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('identiv_velocity', 'hirsch', 'velocity', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('identiv_velocity', 'identiv', 'velocity', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iec_60870_5_104', 'freyrscada', 'iec-60870-5-104', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iec_60870_5_104', 'openscada', 'iec_60870-5-104', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iec_60870_5_104', 'siemens', 'iec_104', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iec_61850_mms', 'libiec61850', 'libiec61850', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iec_61850_mms', 'schweitzer_engineering_laboratories', 'sel-3530_rtac', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iec_61850_mms', 'sel', 'sel-3530', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('igloohome', 'igloohome', 'smart_lock_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('igloohome', 'igloohome', 'smart_padlock', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iis', 'microsoft', 'internet_information_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iis', 'microsoft', 'internet_information_services', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ikea_dirigera', 'ikea', 'dirigera', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ikea_dirigera', 'ikea_of_sweden', 'dirigera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ikea_tradfri_gateway', 'ikea', 'tradfri_gateway_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ikea_tradfri_gateway', 'ikea_of_sweden', 'tradfri_gateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('imap', 'dovecot', 'dovecot', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('indra_ticketing', 'indra', 'ticketing', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('indra_ticketing', 'indracompany', 'ticketing_system', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('influxdb', 'influxdata', 'influxdb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('innogy_ebox', 'eon', 'drive_v2g', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('innogy_ebox', 'innogy', 'eboxprofessional_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('intelight_x1', 'intelight', 'maxtime', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('intelight_x1', 'intelight', 'x1', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ipmi', 'intel', 'ipmi', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ipp', 'openprinting', 'ipp_everywhere', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ipp', 'pwg', 'ipp', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ipsec_ike', 'libreswan', 'libreswan', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ipsec_ike', 'strongswan', 'strongswan', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('irc', 'inspircd', 'inspircd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('irc', 'ircd-hybrid', 'ircd-hybrid', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('irc', 'unrealircd', 'unrealircd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iscsi_target', 'linux-iscsi', 'lio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iscsi_target', 'open-iscsi', 'open-iscsi', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('iscsi_target', 'openatom', 'tgt', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('istio_pilot', 'google', 'istio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('istio_pilot', 'istio', 'istio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('itron_openway', 'itron', 'centron', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('itron_openway', 'itron', 'openway_riva', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('java', 'oracle', 'java_se', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('java', 'oracle', 'jdk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('java', 'oracle', 'jre', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jboss', 'redhat', 'jboss_application_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jboss', 'redhat', 'jboss_enterprise_application_platform', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jdk', 'oracle', 'jdk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jdk', 'sun', 'jdk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jenkins', 'cloudbees', 'jenkins', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jenkins', 'jenkins', 'jenkins', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jetbrains_teamcity', 'jetbrains', 'teamcity', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jetdirect', 'hp', 'jetdirect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jetty', 'eclipse', 'jetty', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jetty', 'mortbay', 'jetty', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jira', 'atlassian', 'jira', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jira', 'atlassian', 'jira_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jira', 'atlassian', 'jira_software', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('john_deere_jdlink', 'deere', '4g_mtg', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('john_deere_jdlink', 'deere', 'jdlink', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('john_deere_jdlink', 'deere', 'operations_center', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('johnson_controls', 'johnsoncontrols', 'facility_explorer', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('johnson_controls', 'johnsoncontrols', 'metasys', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('joomla', 'joomla', 'joomla\!', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jre', 'oracle', 'jre', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('jre', 'sun', 'jre', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('juniper_junos', 'juniper', 'junos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('juniper_junos', 'juniper', 'junos_os', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kafka', 'apache', 'kafka', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kamailio', 'kamailio', 'kamailio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('keba_charger', 'keba', 'kecontact_p20', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('keba_charger', 'keba', 'kecontact_p30', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('keba_p40', 'keba', 'kecontact_p40_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('keycloak', 'keycloak', 'keycloak', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('keycloak', 'redhat', 'keycloak', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kibana', 'elastic', 'kibana', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kieback_peter_bacnet', 'kieback-peter', 'dms', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kmc_controls', 'kmccontrols', 'bac-9300', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('knot_resolver', 'cz.nic', 'knot_resolver', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('knot_resolver', 'cz_nic', 'knot-resolver', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('knx_ip', 'calimero-project', 'calimero-core', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('knx_ip', 'knx', 'knxd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('knx_ip', 'knx_association', 'knx_falcon_sdk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kong', 'konghq', 'kong', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kubelet', 'kubernetes', 'kubernetes', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kubernetes', 'kubernetes', 'kubernetes', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kuka_krc', 'kuka', 'krc4', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kuka_krc', 'kuka', 'system_software', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kuma_cp', 'konghq', 'kuma', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kuma_cp', 'kuma', 'kuma', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kwikset_halo', 'kwikset', 'halo', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kwikset_halo', 'spectrum_brands', 'kwikset_halo_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kyocera_printer', 'kyoceradocumentsolutions', 'command_center_rx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('kyocera_printer', 'kyoceramita', 'command_center_rx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ldap', 'openldap', 'openldap', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lely_astronaut', 'lely', 'astronaut_a5_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lely_astronaut', 'lely', 'discovery_120', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lely_astronaut', 'lely', 'vector', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lenel_onguard', 'carrier', 'lenel_onguard', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lenel_onguard', 'lenel', 'onguard', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lexmark_printer', 'lexmark', 'cx410_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lexmark_printer', 'lexmark', 'ms410_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lexmark_printer', 'lexmark', 'mx410_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lg_thinq', 'lg', 'smartthinq_app', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lg_thinq', 'lg', 'thinq', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lg_thinq', 'lge', 'thinq', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lg_webos_tv', 'lg', 'webos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lg_webos_tv', 'lg', 'webos_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lg_webos_tv', 'lge', 'webos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lg_webos_tv', 'lge', 'webos_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('libssh', 'libssh', 'libssh', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('liebherr_smartdevicebox', 'liebherr', 'smartdevice_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('liebherr_smartdevicebox', 'liebherr', 'smartdevicebox', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lifx_bulb', 'lifx', 'lifx_bulb_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lifx_bulb', 'lifx', 'smart_bulb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lightning_network_daemon', 'lightning', 'lnd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lightning_network_daemon', 'lightningnetwork', 'lnd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lighttpd', 'lighttpd', 'lighttpd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lindsay_fieldnet', 'lindsay', 'fieldnet_advisor', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lindsay_fieldnet', 'lindsay-corporation', 'fieldnet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('linkerd_proxy', 'buoyant', 'linkerd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('linkerd_proxy', 'linkerd', 'linkerd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('linkerd_proxy', 'linkerd', 'linkerd2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('litecoin_core', 'litecoin', 'litecoin', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('litecoin_core', 'litecoin-project', 'litecoin', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('litespeed', 'litespeedtech', 'litespeed_web_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('litespeed', 'litespeedtech', 'openlitespeed', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lockly_secure', 'lockly', 'secure_pro_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lockly_secure', 'lockly', 'vision_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('logstash', 'elastic', 'logstash', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lonworks', 'echelon', 'i.lon', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lonworks', 'echelon', 'lonworks', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lonworks', 'echelon', 'smartserver_2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lustre', 'ddn', 'lustre', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lustre', 'lustre', 'lustre', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lutron_homeworks', 'lutron', 'caseta_pro', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lutron_homeworks', 'lutron', 'homeworks_qs', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lutron_homeworks', 'lutron', 'radiora2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lwm2m', 'eclipse', 'leshan', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lwm2m', 'eclipse', 'wakaama', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('lwm2m', 'openmobilealliance', 'lwm2m', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('maeve_csms', 'subnetzero', 'maeve', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('maeve_csms', 'thoughtworks', 'maeve_csms', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('magento', 'adobe', 'commerce', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('magento', 'adobe', 'magento', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('magento', 'magento', 'magento', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mailcow', 'mailcow', 'mailcow_dockerized', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mariadb', 'mariadb', 'mariadb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('matter_node', 'csa-iot', 'matter', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('matter_node', 'project-chip', 'connectedhomeip', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('matter_otbr', 'google', 'openthread_border_router', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('matter_otbr', 'nordicsemi', 'openthread_border_router', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('matter_otbr', 'openthread', 'ot-br-posix', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mautic', 'mautic', 'mautic', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mccain_atc', 'mccain', 'atc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mccain_atc', 'mccain', 'atc_eX', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mediawiki', 'mediawiki', 'mediawiki', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mediawiki', 'wikimedia', 'mediawiki', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('memcached', 'memcached', 'memcached', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('miele_xkm', 'miele', 'miele_at_home', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('miele_xkm', 'miele', 'xgw3000', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('miele_xkm', 'miele', 'xkm_3100w', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mikrotik_routeros', 'mikrotik', 'router_os', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mikrotik_routeros', 'mikrotik', 'routeros', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('milestone_xprotect', 'milestone', 'xprotect_corporate', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('milestone_xprotect', 'milestone', 'xprotect_smart_client', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('milestone_xprotect', 'milestonesys', 'xprotect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('minecraft_server', 'microsoft', 'minecraft', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('minecraft_server', 'mojang', 'minecraft', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('minio_server', 'minio', 'minio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mirth_connect', 'mirth', 'mirth_connect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mirth_connect', 'nextgen', 'connect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mirth_connect', 'nextgen', 'mirth_connect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mitel_sip', 'mitel', 'micollab', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mitel_sip', 'mitel', 'mivoice_connect', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mitsubishi_melsec', 'mitsubishi', 'melsec', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mitsubishi_melsec', 'mitsubishielectric', 'melsec_iq-f_series', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mitsubishi_melsec', 'mitsubishielectric', 'melsec_iq-r_series', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mitsubishi_melsec', 'mitsubishielectric', 'melsec_q_series', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('modbus', 'modbus', 'modbus', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('monero_node', 'monero', 'monero', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('monero_node', 'monero-project', 'monero', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mongodb', 'mongodb', 'mongodb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('moodle', 'moodle', 'moodle', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('morley_facp', 'honeywell', 'morley_zx5', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('morley_facp', 'morley-ias', 'zx-series', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('moxa_iot', 'moxa', 'iologik_e1212_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('moxa_iot', 'moxa', 'mgate_mb3170_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('moxa_iot', 'moxa', 'uc-8112-me-t-linux', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mqtt', 'eclipse', 'mosquitto', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mssql', 'microsoft', 'sql_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mueller_mi', 'mueller', 'mi.net', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mueller_mi', 'mueller-water-products', 'hydro-guard', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('myenergi_zappi', 'myenergi', 'eddi_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('myenergi_zappi', 'myenergi', 'zappi_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mysql', 'mysql', 'mysql', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('mysql', 'oracle', 'mysql', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nanoleaf_aurora', 'nanoleaf', 'aurora', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nanoleaf_aurora', 'nanoleaf', 'canvas_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nanoleaf_aurora', 'nanoleaf', 'light_panels_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nats', 'nats', 'nats-server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nats', 'synadia', 'nats_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nedap_aeos', 'nedap', 'aeos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nedap_aeos', 'nedap-security-management', 'aeos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nedap_cowcontrol', 'nedap', 'smarttag_neck', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nedap_cowcontrol', 'nedap-livestock', 'cowcontrol', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nest_doorbell', 'google', 'nest_cam', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nest_doorbell', 'google', 'nest_doorbell', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nest_doorbell', 'nest', 'doorbell_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('netafim_netbeat', 'netafim', 'growsphere', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('netafim_netbeat', 'netafim', 'netbeat_controller', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('netapp_ontap', 'netapp', 'data_ontap', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('netapp_ontap', 'netapp', 'ontap', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('netbackup', 'veritas', 'appliance', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('netbackup', 'veritas', 'netbackup', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nextcloud', 'nextcloud', 'nextcloud', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nextcloud', 'nextcloud', 'nextcloud_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nexus', 'sonatype', 'nexus', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nexus', 'sonatype', 'nexus_repository_manager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nfs_server', 'freebsd', 'freebsd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nfs_server', 'linux', 'linux_kernel', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nfs_server', 'openbsd', 'openbsd', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nginx', 'f5', 'nginx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nginx', 'nginx', 'nginx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nginx-plus', 'f5', 'nginx_plus', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nifi', 'apache', 'nifi', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nmea0183', 'iec', '61162', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nmea0183', 'nmea', 'nmea_0183', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('node', 'nodejs', 'node.js', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nodejs', 'node.js', 'node.js', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nodejs', 'nodejs', 'node.js', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('nomad', 'hashicorp', 'nomad', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('notifier_onyx', 'honeywell', 'notifier_inspire_facp_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('notifier_onyx', 'honeywell', 'onyx_nfn_gateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('notifier_onyx', 'honeywell', 'onyxworks', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ntp', 'ntp', 'ntp', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ocpp', 'ocpp', 'ocpp-j', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ocpp', 'openchargealliance', 'ocpp', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ohme_home_pro', 'ohme', 'home_pro_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('omron_plc', 'omron', 'cj2m', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('omron_plc', 'omron', 'nj-series_machine_automation_controllers', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('omron_plc', 'omron', 'sysmac_studio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('opcua', 'opcfoundation', 'ua-.net-standard', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('opcua', 'open62541', 'open62541', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('opcua', 'unified_automation', 'uasdk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openemr', 'open-emr', 'openemr', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openemr', 'openemr', 'openemr', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openhab', 'openhab', 'openhab', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openjdk', 'oracle', 'openjdk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openjdk', 'redhat', 'openjdk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openmrs', 'openmrs', 'openmrs', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openresty', 'openresty', 'openresty', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openshift', 'redhat', 'openshift', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openshift', 'redhat', 'openshift_container_platform', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('opensips', 'opensips', 'opensips', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openssh', 'openbsd', 'openssh', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openssh', 'openssh', 'openssh', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openssl', 'openssl', 'openssl', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openstack_keystone', 'openstack', 'keystone', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openstack_keystone', 'redhat', 'openstack_platform_director', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openstack_neutron', 'openstack', 'neutron', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openstack_neutron', 'redhat', 'openstack_platform', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openstack_nova', 'openstack', 'nova', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openstack_nova', 'redhat', 'openstack_platform', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openvpn', 'openvpn', 'openvpn', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('openvpn', 'openvpn', 'openvpn_access_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('oracle_database', 'oracle', 'database', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('oracle_database', 'oracle', 'database_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('orthanc_dicom', 'orthanc-server', 'orthanc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('orthanc_dicom', 'osimis', 'orthanc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('osirix', 'pixmeo', 'osirix', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('osirix', 'pixmeo', 'osirix_md', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('osisoft_pi', 'aveva', 'pi_data_archive', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('osisoft_pi', 'aveva', 'pi_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('osisoft_pi', 'osisoft', 'pi_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('osisoft_pi', 'osisoft', 'pi_web_api', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ovirt_engine', 'ovirt', 'engine', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ovirt_engine', 'ovirt', 'ovirt-engine', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ovirt_engine', 'redhat', 'virtualization', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('owncloud', 'owncloud', 'core', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('owncloud', 'owncloud', 'owncloud', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('pacscube', 'pacscube', 'pacscube', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('parkline_ev_ru', 'parkline', 'ev_charger_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('passenger', 'phusion', 'passenger', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('paxton_net2', 'paxton', 'net2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('paxton_net2', 'paxton-access', 'net2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('perco_web', 'perco', 's-20', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('perco_web', 'perco', 'web2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('perl', 'perl', 'perl', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('philips_hue_v2', 'philips', 'hue_bridge_v2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('philips_hue_v2', 'signify', 'hue_bridge_2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('philips_hue_v2', 'signify_netherlands', 'hue_bridge_2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phoenix_contact_charx', 'phoenixcontact', 'charx_sec-3100_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phoenix_contact_plc', 'phoenixcontact', 'axc_1050', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phoenix_contact_plc', 'phoenixcontact', 'axc_3050', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phoenix_contact_plc', 'phoenixcontact', 'ilc_151_eth', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phoenix_contact_router', 'phoenixcontact', 'fl_mguard_rs4000_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phoenix_contact_router', 'phoenixcontact', 'fl_switch_3005', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phoenix_contact_router', 'phoenixcontact', 'tc_router_3002t-4g', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('php', 'php', 'php', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('php-fpm', 'php', 'php', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phpbb', 'phpbb', 'phpbb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('phpmyadmin', 'phpmyadmin', 'phpmyadmin', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('polycom_phone', 'poly', 'ucs', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('polycom_phone', 'polycom', 'ucs', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('polycom_phone', 'polycom', 'vvx_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('pop3', 'dovecot', 'dovecot', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('postfix', 'postfix', 'postfix', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('postgresql', 'postgresql', 'postgresql', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('prometheus', 'prometheus', 'prometheus', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('prometheus-am', 'prometheus', 'alertmanager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('prometheus_alertmanager', 'prometheus', 'alertmanager', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('prometheus_pushgateway', 'prometheus', 'pushgateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('proxmox_ve', 'proxmox', 've', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('proxmox_ve', 'proxmox', 'virtual_environment', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('proxmox_ve', 'proxmox-server-solutions', 'proxmox_ve', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('pulse-vpn', 'pulsesecure', 'pulse_connect_secure', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('puma', 'puma', 'puma', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('pure_storage', 'pure_storage', 'purity_oe', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('pure_storage', 'purestorage', 'purity', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('python', 'python', 'python', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('python3', 'python', 'python', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rabbitmq', 'pivotal_software', 'rabbitmq', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rabbitmq', 'rabbitmq', 'rabbitmq', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rain_bird_esp', 'rain_bird', 'lnk_wifi_module', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rain_bird_esp', 'rainbird', 'esp-me_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rain_bird_esp', 'rainbird', 'esp-tm2_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rancher', 'rancher', 'rancher', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rancher', 'suse', 'rancher', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('raven_viper', 'raven_industries', 'viper_4+_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('raven_viper', 'ravenind', 'viper_4', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rdp', 'microsoft', 'remote_desktop', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rdp', 'microsoft', 'windows', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('red_lion_iot', 'red_lion_controls', 'graphite_hmi_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('red_lion_iot', 'redlion', 'flexedge', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('red_lion_iot', 'redlion', 'n-tron_702-w', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('redis', 'redis', 'redis', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('redmine', 'redmine', 'redmine', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('reolink_camera', 'reolink', 'camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ricoh_printer', 'ricoh', 'im_c4500_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ricoh_printer', 'ricoh', 'printer_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ring_doorbell', 'amazon', 'ring_doorbell_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ring_doorbell', 'ring', 'stickup_cam_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ring_doorbell', 'ring', 'video_doorbell', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rockwell_factorytalk', 'rockwell_automation', 'factorytalk_linx_gateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rockwell_factorytalk', 'rockwellautomation', 'factorytalk_linx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rockwell_logix', 'rockwellautomation', 'compactlogix', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rockwell_logix', 'rockwellautomation', 'controllogix', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rockwell_logix', 'rockwellautomation', 'rslogix', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rockwell_logix', 'rockwellautomation', 'studio_5000_logix_designer', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('roku_tv', 'roku', 'roku', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('roku_tv', 'roku', 'roku_os', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('roku_tv', 'roku', 'streaming_player_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('roku_tv', 'roku', 'tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ros2_dds', 'openrobotics', 'ros2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ros2_dds', 'ros', 'ros2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ros_master', 'openrobotics', 'ros', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ros_master', 'ros', 'ros', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rsync', 'openbsd', 'rsync', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rsync', 'rsync', 'rsync', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rsync', 'samba', 'rsync', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rubrik_cdm', 'rubrik', 'cdm', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('rubrik_cdm', 'rubrik', 'cloud_data_management', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ruby', 'ruby-lang', 'ruby', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('s2_netbox', 'lenel', 'netbox', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('s2_netbox', 's2', 'netbox', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_smartthings', 'samsung', 'smartthings', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_smartthings', 'samsung', 'smartthings_hub_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_smartthings', 'samsung', 'smartthings_station_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_smartthings_hub', 'aeotec', 'smartthings_hub_v3', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_smartthings_hub', 'samsung', 'smartthings_hub_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_smartthings_hub', 'smartthings', 'hub_v3_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_tizen_tv', 'samsung', 'smart_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_tizen_tv', 'samsung', 'tizen', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_tizen_tv', 'samsung', 'tizen_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('samsung_tizen_tv', 'tizenproject', 'tizen', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sangoma_pbx', 'sangoma', 'freepbx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sangoma_pbx', 'sangoma', 'pbxact', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('scheidt_bachmann_entervo', 'scheidt-bachmann', 'entervo', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schlage_encode', 'allegion', 'schlage_encode_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schlage_encode', 'schlage', 'encode', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schneider_electric_modicon', 'schneider-electric', 'ecostruxure_control_expert', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schneider_electric_modicon', 'schneider-electric', 'modicon', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schneider_electric_modicon', 'schneider-electric', 'modicon_m340', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schneider_evlink', 'schneider-electric', 'evlink_city', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schneider_evlink', 'schneider-electric', 'evlink_parking', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schrack_seconet', 'schrack-seconet', 'integral_ip', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('schrack_seconet', 'schrack-seconet', 'integral_mx', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('scylla', 'scylladb', 'scylla', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sel_3373', 'schweitzer', 'sel-3373', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sel_3373', 'selinc', 'sel-3373', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sel_rtac', 'schweitzer_engineering_laboratories', 'sel-3530_rtac', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sel_rtac', 'sel', 'rtac', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sel_rtac', 'sel', 'sel-3530-4', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sendmail', 'proofpoint', 'sendmail', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sendmail', 'sendmail', 'sendmail', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sensus_flexnet', 'sensus', 'flexnet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sensus_flexnet', 'xylem', 'sensus_flexnet', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sharepoint', 'microsoft', 'sharepoint_foundation', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sharepoint', 'microsoft', 'sharepoint_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('shelly', 'allterco_robotics', 'shelly_smart_relay', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('shelly', 'shelly', 'shelly_pro_4pm_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_cerberus', 'siemens', 'cerberus_dms', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_cerberus', 'siemens', 'cerberus_pro_fc72x', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_cerberus', 'siemens', 'cerberus_pro_fs720', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_iot2050', 'siemens', 'iot2050_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_iot2050', 'siemens', 'simatic_iot2040', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_iot2050', 'siemens', 'simatic_iot2050', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_sicam_pas', 'siemens', 'sicam', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_sicam_pas', 'siemens', 'sicam_pas', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_simatic', 'siemens', 'simatic_s7-1200', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_simatic', 'siemens', 'simatic_s7-1500', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_simatic', 'siemens', 'simatic_s7-300', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_simatic', 'siemens', 'simatic_s7-400', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_simatic', 'siemens', 'step_7', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_sitraffic', 'siemens', 'scala', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_sitraffic', 'siemens', 'sitraffic_concert', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('siemens_sitraffic', 'siemens', 'sx_traffic_controller', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('signet_dc', 'signet', 'ev_charger_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sigur_access', 'sigur', 'access_management', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('simplex_4100es', 'johnsoncontrols', 'simplex_4100es_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('simplex_4100es', 'simplex', '4100es_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('simplex_4100es', 'tyco', 'simplex_4100es', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sip_server', 'ietf', 'session_initiation_protocol', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('skidata_parking', 'skidata', 'parking_management_system', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sma_inverter', 'sma', 'sunny_boy_storage', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sma_inverter', 'sma', 'sunny_webbox', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('smappee_ev_wall', 'smappee', 'ev_wall_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('smb', 'microsoft', 'windows', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('smb', 'samba', 'samba', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('snmp', 'net-snmp', 'net-snmp', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('software_house_ccure', 'johnsoncontrols', 'c-cure_9000', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('software_house_ccure', 'softwarehouse', 'c-cure_9000', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('software_house_ccure', 'tyco', 'c-cure_9000', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('software_house_istar', 'johnsoncontrols', 'istar_ultra', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('software_house_istar', 'softwarehouse', 'istar_ultra_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('software_house_istar', 'tyco', 'istar_ultra', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('solr', 'apache', 'solr', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sonarqube', 'sonarsource', 'sonarqube', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sonoff_zbbridge', 'itead', 'sonoff_zbbridge_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sonoff_zbbridge', 'sonoff', 'zbbridge', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sonos', 'sonos', 'controller', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sonos', 'sonos', 'one_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sonos', 'sonos', 'play_5', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sonos', 'sonos', 'sonos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sony_bravia_tv', 'sony', 'android_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sony_bravia_tv', 'sony', 'bravia', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sony_bravia_tv', 'sony', 'bravia_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sony_bravia_tv', 'sony', 'smart_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('spark', 'apache', 'spark', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('splunk', 'splunk', 'splunk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('splunk', 'splunk', 'splunk_cloud', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('splunk', 'splunk', 'splunk_enterprise', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('squid', 'squid-cache', 'squid', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ssh', 'openbsd', 'openssh', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ssh', 'openssh', 'openssh', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('staubli_cs9', 'staeubli', 'cs9', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('staubli_cs9', 'staubli', 'cs9', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('steam_dedicated_server', 'valve', 'steam', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('steam_dedicated_server', 'valvesoftware', 'steam', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('steve_ocpp', 'rwth-i5', 'steve', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('steve_ocpp', 'rwth-i5-it', 'steve', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('strapi', 'strapi', 'strapi', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('struts', 'apache', 'struts', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('sun_one', 'sun', 'one_web_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('superset', 'apache', 'superset', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('suprema_biostar', 'suprema', 'biostar_2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('suprema_biostar', 'supremainc', 'biostar_2', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('swann_dvr', 'swann', 'dvr_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('swann_dvr', 'swann', 'nvr_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('swann_dvr', 'swann_communications', 'dvr_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('swarco_traffic', 'swarco', 'actros', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('swarco_traffic', 'swarco', 'trafficcontroller', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('synchrophasor_pmu', 'ieee', 'c37.118', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tasmota', 'tasmota', 'tasmota', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tcl_android_tv', 'tcl', 'android_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tcl_android_tv', 'tcl', 'google_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tcl_android_tv', 'tcl', 'smart_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tcx_phone_system', '3cx', '3cx_phone_system', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('telnet', 'gnu', 'inetutils', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('terraform', 'hashicorp', 'terraform', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tesla_wall_connector', 'tesla', 'wall_connector_gen_3_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('thales_revenue', 'thales', 'revenue_collection_system', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('thales_revenue', 'thales', 'transport_ticketing_system', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('thin', 'thin', 'thin', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tomcat', 'apache', 'tomcat', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('topcon_x35', 'topcon', 'x14_console', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('topcon_x35', 'topcon', 'x35_ag_console_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('toro_tempus', 'toro', 'sentinel_central_control', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('toro_tempus', 'toro', 'tempus_air_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('touchenergy_ru', 'touchenergy', 'ac_charger_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('traefik', 'containous', 'traefik', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('traefik', 'traefik', 'traefik', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('trafficware_atc', 'cubic_its', 'scout', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('trafficware_atc', 'trafficware', 'commander', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('trafficware_atc', 'trafficware', 'scout', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('trane_bacnet', 'trane', 'tracer_sc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tridium_niagara', 'tridium', 'niagara_4', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tridium_niagara', 'tridium', 'niagara_ax_framework', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tridium_niagara', 'tridium', 'niagara_framework', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tridonic_dali', 'tridonic', 'dali_gateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tridonic_dali', 'tridonic', 'x_gateway', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('trimble_ag', 'trimble', 'ag_software', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('trimble_ag', 'trimble', 'agdata_solutions', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('trimble_ag', 'trimble', 'tmx-2050_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tritium_pkm', 'tritium', 'pk-series_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tritium_pkm', 'tritium', 'rt175s_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tuya_device', 'tuya', 'smart_device_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tuya_device', 'tuya', 'smart_life', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('tuya_device', 'tuya', 'tuya_convenience_go_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('typo3', 'typo3', 'typo3', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ubiquiti_camera', 'ubiquiti_networks', 'unifi_video', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ubiquiti_camera', 'ui', 'unifi_video', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ubiquiti_edgeos', 'ubiquiti', 'edgerouter_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ubiquiti_edgeos', 'ubiquiti_networks', 'edgeos', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('ubiquiti_edgeos', 'ui', 'unifi', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('unbound', 'nlnet_labs', 'unbound', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('unbound', 'nlnetlabs', 'unbound', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('unicorn', 'unicorn_project', 'unicorn', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('universal_robots', 'universal-robots', 'polyscope', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('universal_robots', 'universal-robots', 'ursoftware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('universal_robots', 'universal_robots', 'urcontrol', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('uwsgi', 'unbit', 'uwsgi', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('v2c_trydan', 'v2c', 'trydan_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('valley_irrigation', 'valley', 'icon10', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('valley_irrigation', 'valley_irrigation', 'icon_x_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vanderbilt_aliro', 'vanderbilt', 'aliro', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vanderbilt_aliro', 'vanderbilt', 'siveillance_access', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('varnish', 'varnish-software', 'varnish_cache_plus', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('varnish', 'varnish_cache_project', 'varnish_cache', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vault', 'hashicorp', 'vault', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vcenter', 'vmware', 'vcenter_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('veeam_backup', 'veeam', 'backup_&_replication', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('veeam_backup', 'veeam', 'backup_for_microsoft_365', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('veeam_backup', 'veeam', 'veeam_backup_&_replication', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('victoria_metrics', 'victoriametrics', 'victoriametrics', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vivotek_camera', 'vivotek', 'ip_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vivotek_camera', 'vivotek', 'network_camera_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vizio_smartcast', 'vizio', 'smart_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vizio_smartcast', 'vizio', 'smartcast', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vizio_smartcast', 'vizio', 'smartcast_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vnc', 'realvnc', 'vnc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vnc', 'tightvnc', 'tightvnc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('vsphere', 'vmware', 'vsphere', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wago_plc', 'wago', '750_series', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wago_plc', 'wago', 'pfc200_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wallbox_mywallbox', 'wallbox', 'copper_sb_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wallbox_mywallbox', 'wallbox', 'mywallbox', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wallbox_mywallbox', 'wallbox', 'pulsar_plus_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wallbox_pulsar', 'wallbox', 'pulsar_plus_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wallbox_quasar', 'wallbox', 'quasar_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('webasto_live', 'webasto', 'live_charging_station', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('webrick', 'ruby-lang', 'ruby', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('werkzeug', 'pallets', 'werkzeug', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('werkzeug', 'palletsprojects', 'werkzeug', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('whirlpool_smart', 'whirlpool', '6th_sense_live', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('whirlpool_smart', 'whirlpool', 'smart_appliance_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('whirlpool_smart', 'whirlpool', 'whirlpool_app', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wildfly', 'redhat', 'wildfly', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wildfly', 'wildfly', 'wildfly', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wireguard', 'wireguard', 'wireguard', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wled', 'wled', 'wled', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wonderware_intouch', 'aveva', 'intouch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wonderware_intouch', 'aveva', 'system_platform', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wonderware_intouch', 'schneider-electric', 'intouch_access_anywhere', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wonderware_intouch', 'wonderware', 'intouch', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('woodpecker_ci', 'woodpecker', 'woodpecker', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('woodpecker_ci', 'woodpecker-ci', 'woodpecker', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wordpress', 'wordpress', 'wordpress', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wordpress', 'wordpress.org', 'wordpress', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wyze_cam', 'wyze', 'cam_v3_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('wyze_cam', 'wyze_labs', 'cam_pan_v2_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('x11', 'x.org', 'x_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('x11', 'xfree86', 'xfree86', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('x11', 'xorg', 'x_server', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xcp_ng', 'vates', 'xcp-ng', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xcp_ng', 'xcp-ng', 'xcp-ng', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xenserver_xapi', 'citrix', 'hypervisor', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xenserver_xapi', 'citrix', 'xenserver', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xerox_printer', 'xerox', 'phaser', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xerox_printer', 'xerox', 'workcentre', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xiaomi_mi_tv', 'xiaomi', 'mi_tv', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xiaomi_mi_tv', 'xiaomi', 'mi_tv_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xiaomi_mi_tv', 'xiaomi', 'mitv_stick', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xiaomi_miio_device', 'xiaomi', 'mi_home', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xiaomi_miio_device', 'xiaomi', 'mihome', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('xiaomi_miio_device', 'xiaomi', 'miio', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yale_assure', 'assa_abloy', 'yale_assure_lock_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yale_assure', 'yale', 'assure_lock', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yamaha_musiccast', 'yamaha', 'musiccast', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yamaha_musiccast', 'yamahacorporation', 'musiccast', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yaskawa_motoman', 'yaskawa', 'motoman', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yaskawa_motoman', 'yaskawa', 'yrc1000', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yealink_phone', 'yealink', 'phone_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yealink_phone', 'yealink', 'sip-t46s_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yealink_phone', 'yealink', 'sip-t48u_firmware', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yeelight', 'xiaomi', 'yeelight', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yeelight', 'yeelight', 'smart_bulb', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yeelight', 'yeelink', 'yeelight', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yokogawa_centum', 'yokogawa', 'centum_cs_3000', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yokogawa_centum', 'yokogawa', 'centum_vp', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('yokogawa_centum', 'yokogawa', 'exaopc', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('zigbee2mqtt', 'koenkk', 'zigbee2mqtt', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('zigbee2mqtt', 'zigbee2mqtt', 'zigbee2mqtt', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('zkteco_biosecurity', 'zkteco', 'pushsdk', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('zkteco_biosecurity', 'zkteco', 'zkbiosecurity', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('zookeeper', 'apache', 'zookeeper', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('zwave_js_ui', 'zwave-js', 'zwave-js-ui', 'builtin') ON CONFLICT DO NOTHING;
INSERT INTO uv_cpe_product_map (product_key, vendor, product, source) VALUES ('zwave_js_ui', 'zwave-js', 'zwavejs2mqtt', 'builtin') ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION uv_scan_cancel_notify()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.cancel_requested IS TRUE AND
       (OLD.cancel_requested IS DISTINCT FROM NEW.cancel_requested) THEN
        PERFORM pg_notify('uv_scan_cancel', NEW.id::text);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER uv_scan_cancel_trigger
    AFTER UPDATE OF cancel_requested ON uv_scan
    FOR EACH ROW
    EXECUTE FUNCTION uv_scan_cancel_notify();

CREATE OR REPLACE FUNCTION uv_scan_pause_notify()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.pause_requested IS TRUE AND
       (OLD.pause_requested IS DISTINCT FROM NEW.pause_requested) THEN
        PERFORM pg_notify('uv_scan_pause', NEW.id::text);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER uv_scan_pause_trigger
    AFTER UPDATE OF pause_requested ON uv_scan
    FOR EACH ROW
    EXECUTE FUNCTION uv_scan_pause_notify();

CREATE OR REPLACE FUNCTION uv_scan_event_notify() RETURNS TRIGGER AS $$
DECLARE payload JSONB;
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        payload := jsonb_build_object(
            'type', 'scan.status',
            'scan_id', NEW.id,
            'data', jsonb_build_object(
                'status', NEW.status,
                'started_at', NEW.started_at,
                'finished_at', NEW.finished_at,
                'error', NEW.error,
                'cancel_requested', NEW.cancel_requested,
                'pause_requested', NEW.pause_requested
            )
        );
        PERFORM pg_notify('uv_event', payload::text);
    END IF;

    IF NEW.stats IS DISTINCT FROM OLD.stats
        OR NEW.stats_updated_at IS DISTINCT FROM OLD.stats_updated_at THEN
        payload := jsonb_build_object(
            'type', 'scan.stats',
            'scan_id', NEW.id,
            'data', jsonb_build_object('stats', NEW.stats)
        );
        PERFORM pg_notify('uv_event', payload::text);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER uv_scan_event_trigger
    AFTER UPDATE ON uv_scan
    FOR EACH ROW
    EXECUTE FUNCTION uv_scan_event_notify();

CREATE OR REPLACE FUNCTION uv_service_snapshot_notify() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('uv_event', jsonb_build_object(
        'type', 'scan.snapshot',
        'scan_id', NEW.scan_id,
        'data', jsonb_build_object(
            'host_id', NEW.host_id,
            'ip', NEW.ip::text
        )
    )::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER uv_service_snapshot_event_trigger
    AFTER INSERT ON uv_service_snapshot
    FOR EACH ROW
    EXECUTE FUNCTION uv_service_snapshot_notify();

CREATE OR REPLACE FUNCTION uv_scan_delta_notify() RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('uv_event', jsonb_build_object(
        'type', 'scan.delta',
        'scan_id', NEW.scan_id,
        'data', jsonb_build_object(
            'new_services', NEW.new_services,
            'disappeared_services', NEW.disappeared_services,
            'changed_services', NEW.changed_services,
            'previous_scan_id', NEW.previous_scan_id
        )
    )::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER uv_scan_delta_event_trigger
    AFTER INSERT ON uv_scan_delta_summary
    FOR EACH ROW
    EXECUTE FUNCTION uv_scan_delta_notify();

CREATE OR REPLACE FUNCTION uv_alert_event_notify() RETURNS TRIGGER AS $$
DECLARE rule_name VARCHAR;
BEGIN
    SELECT name INTO rule_name FROM uv_alert_rule WHERE id = NEW.alert_rule_id;

    PERFORM pg_notify('uv_event', jsonb_build_object(
        'type', 'alert.fired',
        'data', jsonb_build_object(
            'alert_rule_id', NEW.alert_rule_id,
            'name', COALESCE(rule_name, ''),
            'hits_count', NEW.hits_count
        )
    )::text);

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER uv_alert_event_trigger
    AFTER INSERT ON uv_alert_event
    FOR EACH ROW
    EXECUTE FUNCTION uv_alert_event_notify();

-- HTTP screenshot capture: stores headless-Chromium rendered thumbnails for
-- HTTP services and a tiny work queue used by the screenshot worker.

CREATE TABLE uv_http_screenshot
(
    service_id       BIGINT      PRIMARY KEY REFERENCES uv_service (id) ON DELETE CASCADE,
    body_sha256      TEXT,
    thumbnail        BYTEA       NOT NULL,
    thumbnail_width  INTEGER     NOT NULL,
    thumbnail_height INTEGER     NOT NULL,
    render_ms        INTEGER     NOT NULL,
    captured_at      TIMESTAMP   NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

ALTER TABLE uv_http_screenshot ALTER COLUMN thumbnail SET STORAGE EXTERNAL;

CREATE INDEX uv_http_screenshot_captured_at_idx
    ON uv_http_screenshot (captured_at);

CREATE TABLE uv_http_screenshot_job
(
    service_id  BIGINT      PRIMARY KEY REFERENCES uv_service (id) ON DELETE CASCADE,
    status      VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts    INTEGER     NOT NULL DEFAULT 0,
    last_error  TEXT,
    enqueued_at TIMESTAMP   NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    updated_at  TIMESTAMP   NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
    CONSTRAINT uv_http_screenshot_job_status_check
        CHECK (status IN ('pending', 'running', 'failed'))
);

CREATE INDEX uv_http_screenshot_job_status_enqueued_idx
    ON uv_http_screenshot_job (status, enqueued_at);

-- Pivot correlation indexes.

CREATE INDEX uv_tls_certificate_fingerprint_sha256_idx
    ON uv_tls_certificate (fingerprint_sha256)
    WHERE fingerprint_sha256 IS NOT NULL;

CREATE INDEX uv_tls_certificate_jarm_fingerprint_idx
    ON uv_tls_certificate (jarm_fingerprint)
    WHERE jarm_fingerprint IS NOT NULL;

CREATE INDEX uv_tls_certificate_ja3s_hash_idx
    ON uv_tls_certificate (ja3s_hash)
    WHERE ja3s_hash IS NOT NULL;

CREATE INDEX uv_tls_certificate_ja4s_hash_idx
    ON uv_tls_certificate (ja4s_hash)
    WHERE ja4s_hash IS NOT NULL;

CREATE INDEX uv_http_response_favicon_hash_idx
    ON uv_http_response (favicon_hash)
    WHERE favicon_hash IS NOT NULL;

-- Attack-surface risk: per-protocol prior table and tunable risk policy.
-- The pkg/risk core resolves p_exposure for each service through this table;
-- operators can override rows to recalibrate without a code release.
-- uv_risk_policy is the singleton weights / decay-parameters / k-coefficient
-- row threaded into every host recompute.

CREATE TABLE uv_risk_protocol_prior
(
    id              BIGSERIAL PRIMARY KEY,
    port_bucket     VARCHAR(32)   NOT NULL,
    protocol_family VARCHAR(32)   NOT NULL,
    p_exposure      NUMERIC(4, 3) NOT NULL,
    prior_alpha     NUMERIC(8, 3) NOT NULL DEFAULT 1.0,
    prior_beta      NUMERIC(8, 3) NOT NULL DEFAULT 1.0,
    notes           TEXT,
    updated_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
    UNIQUE (port_bucket, protocol_family)
);

INSERT INTO uv_risk_protocol_prior (port_bucket, protocol_family, p_exposure, notes) VALUES
    ('database',       'any', 0.50, 'Databases exposed to the internet (mysql/postgres/mongo/redis/elasticsearch/couchdb)'),
    ('broker_cache',   'any', 0.40, 'Brokers/caches: memcached/amqp/kafka/zookeeper'),
    ('remote_desktop', 'any', 0.45, 'RDP/VNC management surfaces'),
    ('plaintext',      'any', 0.35, 'Legacy plaintext: ftp/telnet/smtp/pop3/imap/snmp/ldap/mssql/oracle'),
    ('http',           'web', 0.05, 'Plain HTTP webserver'),
    ('https',          'web', 0.05, 'HTTPS webserver (raised by p_crypto when TLS findings present)'),
    ('other',          'any', 0.10, 'Unclassified TCP/UDP service');

CREATE INDEX uv_risk_protocol_prior_lookup_idx
    ON uv_risk_protocol_prior (port_bucket, protocol_family);

CREATE TABLE uv_risk_policy
(
    id                              BIGSERIAL PRIMARY KEY,
    name                            VARCHAR(64)   NOT NULL UNIQUE,
    k_coefficient                   NUMERIC(5, 3) NOT NULL DEFAULT 4.0,
    weight_blast                    NUMERIC(4, 3) NOT NULL DEFAULT 0.15,
    weight_lateral                  NUMERIC(4, 3) NOT NULL DEFAULT 0.20,
    decay_kev_halflife_days         INTEGER       NOT NULL DEFAULT 365,
    decay_epss_halflife_days        INTEGER       NOT NULL DEFAULT 90,
    decay_recency_halflife_days     INTEGER       NOT NULL DEFAULT 30,
    decay_tls_halflife_days         INTEGER       NOT NULL DEFAULT 60,
    decay_kev_floor                 NUMERIC(4, 3) NOT NULL DEFAULT 0.200,
    decay_epss_floor                NUMERIC(4, 3) NOT NULL DEFAULT 0.300,
    decay_recency_floor             NUMERIC(4, 3) NOT NULL DEFAULT 0.300,
    decay_tls_floor                 NUMERIC(4, 3) NOT NULL DEFAULT 0.300,
    untagged_impact_baseline        NUMERIC(4, 3) NOT NULL DEFAULT 0.400,
    untagged_confidence_cap         NUMERIC(4, 3) NOT NULL DEFAULT 0.550,
    high_risk_threshold             SMALLINT      NOT NULL DEFAULT 65,
    updated_at                      TIMESTAMP     NOT NULL DEFAULT NOW()
);

INSERT INTO uv_risk_policy (name) VALUES ('default');

-- Attack-surface risk: host and service score timeline snapshots.
-- The risksnapshot worker appends one row per host (and optionally per service)
-- whenever the score moves more than RISK_SNAPSHOT_MIN_DELTA or 24h elapses
-- since the previous capture. Retention is enforced by the retention worker
-- (RISK_EVENT_RETENTION_DAYS env var, default 180d).

CREATE TABLE uv_host_risk_snapshot
(
    host_id       BIGINT        NOT NULL REFERENCES uv_host (id) ON DELETE CASCADE,
    captured_at   TIMESTAMP     NOT NULL,
    score         SMALLINT      NOT NULL,
    probability   NUMERIC(5, 4) NOT NULL,
    impact        NUMERIC(5, 4) NOT NULL,
    confidence    NUMERIC(4, 3) NOT NULL,
    risk_factors  JSONB         NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (host_id, captured_at)
);

CREATE INDEX uv_host_risk_snapshot_host_recent_idx
    ON uv_host_risk_snapshot (host_id, captured_at DESC);

CREATE INDEX uv_host_risk_snapshot_captured_idx
    ON uv_host_risk_snapshot (captured_at);

CREATE TABLE uv_service_risk_snapshot
(
    service_id    BIGINT        NOT NULL REFERENCES uv_service (id) ON DELETE CASCADE,
    captured_at   TIMESTAMP     NOT NULL,
    score         SMALLINT      NOT NULL,
    probability   NUMERIC(5, 4) NOT NULL,
    confidence    NUMERIC(4, 3) NOT NULL,
    risk_factors  JSONB         NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (service_id, captured_at)
);

CREATE INDEX uv_service_risk_snapshot_service_recent_idx
    ON uv_service_risk_snapshot (service_id, captured_at DESC);

CREATE INDEX uv_service_risk_snapshot_captured_idx
    ON uv_service_risk_snapshot (captured_at);

-- Attack path: per-host relations (shared subnet/ASN/cert/favicon/JARM/tech)
-- and the materialised centrality scores the network_position channel reads.

CREATE TABLE uv_host_relation
(
    src_host_id   BIGINT       NOT NULL REFERENCES uv_host (id) ON DELETE CASCADE,
    dst_host_id   BIGINT       NOT NULL REFERENCES uv_host (id) ON DELETE CASCADE,
    relation_type VARCHAR(32)  NOT NULL CHECK (relation_type IN (
        'shared_subnet', 'shared_asn', 'shared_cert', 'shared_favicon',
        'shared_jarm', 'shared_techstack', 'shared_dns_root'
    )),
    strength      NUMERIC(4, 3) NOT NULL,
    evidence      JSONB         NOT NULL DEFAULT '{}'::jsonb,
    computed_at   TIMESTAMP     NOT NULL DEFAULT NOW(),
    PRIMARY KEY (src_host_id, dst_host_id, relation_type),
    CHECK (src_host_id <> dst_host_id)
);

CREATE INDEX uv_host_relation_src_idx ON uv_host_relation (src_host_id, strength DESC);
CREATE INDEX uv_host_relation_dst_idx ON uv_host_relation (dst_host_id, strength DESC);
CREATE INDEX uv_host_relation_type_idx ON uv_host_relation (relation_type);

CREATE TABLE uv_host_attack_path_score
(
    host_id                  BIGINT        PRIMARY KEY REFERENCES uv_host (id) ON DELETE CASCADE,
    centrality               NUMERIC(5, 4) NOT NULL DEFAULT 0,
    pivot_score              NUMERIC(5, 4) NOT NULL DEFAULT 0,
    reachable_critical_count INTEGER       NOT NULL DEFAULT 0,
    top_paths                JSONB         NOT NULL DEFAULT '[]'::jsonb,
    computed_at              TIMESTAMP     NOT NULL DEFAULT NOW()
);

CREATE INDEX uv_host_attack_path_centrality_idx ON uv_host_attack_path_score (centrality DESC);

-- Remediation recommendations: ordered list of operator actions the risk
-- service believes would reduce a host's score the most. Fully recomputed
-- from the live signals after every recompute (read-only in the UI).

CREATE TABLE uv_remediation_recommendation
(
    id                   BIGSERIAL PRIMARY KEY,
    host_id              BIGINT       NOT NULL REFERENCES uv_host (id) ON DELETE CASCADE,
    service_id           BIGINT REFERENCES uv_service (id) ON DELETE CASCADE,
    action_code          VARCHAR(64)  NOT NULL,
    label                TEXT         NOT NULL,
    expected_delta_p     NUMERIC(4, 3) NOT NULL DEFAULT 0,
    expected_delta_score SMALLINT     NOT NULL DEFAULT 0,
    evidence             JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX uv_remediation_host_idx
    ON uv_remediation_recommendation (host_id, expected_delta_score DESC);
