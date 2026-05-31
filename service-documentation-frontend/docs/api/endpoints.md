# Endpoints

The full list of REST endpoints. Roles: `V` = viewer, `O` = operator,
`A` = admin; the lowest sufficient role is shown.

## Public

| Method | Path               | Role   | Purpose                          |
| ------ | ------------------ | ------ | -------------------------------- |
| `GET`  | `/livez`           | public | Liveness ping.                   |
| `GET`  | `/readyz`          | public | Readiness + version + commit.    |
| `POST` | `/v1/auth/login`   | public | Issue token pair. Rate-limited.  |
| `POST` | `/v1/auth/refresh` | public | Rotate token pair. Rate-limited. |

## Identity

| Method | Path              | Role | Purpose                                                                                                         |
| ------ | ----------------- | ---- | --------------------------------------------------------------------------------------------------------------- |
| `POST` | `/v1/auth/logout` | V    | Revoke caller's refresh tokens.                                                                                 |
| `GET`  | `/v1/me`          | V    | `{role, user_id}`.                                                                                              |
| `GET`  | `/v1/version`     | V    | `{version, commit, built_at, demo_mode}`. `demo_mode` is `true` when the server runs with `APP_DEMO_MODE=true`. |

## Scans

| Method | Path                              | Role | Purpose                                                      |
| ------ | --------------------------------- | ---- | ------------------------------------------------------------ |
| `POST` | `/v1/scans`                       | O    | Create scan. See [Creating Scans](/scanning/creating-scans). |
| `GET`  | `/v1/scans`                       | V    | List scans.                                                  |
| `GET`  | `/v1/scans/{id}`                  | V    | Scan detail + stats + cursor.                                |
| `POST` | `/v1/scans/{id}/cancel`           | O    | Cancel (transitions to `CANCELED`).                          |
| `POST` | `/v1/scans/{id}/pause`            | O    | Pause running scan.                                          |
| `POST` | `/v1/scans/{id}/resume`           | O    | Resume paused scan.                                          |
| `POST` | `/v1/scans/{id}/restart`          | O    | Reset cursor and re-run.                                     |
| `GET`  | `/v1/scans/{id}/delta`            | V    | Per-scan delta summary.                                      |
| `GET`  | `/v1/scans/{id}/delta/events`     | V    | Per-scan delta events.                                       |
| `GET`  | `/v1/export/scans/{id}/delta.csv` | V    | CSV export of delta events.                                  |

## Scan schedules

| Method   | Path                              | Role | Purpose          |
| -------- | --------------------------------- | ---- | ---------------- |
| `POST`   | `/v1/scan-schedules`              | O    | Create schedule. |
| `GET`    | `/v1/scan-schedules`              | V    | List.            |
| `GET`    | `/v1/scan-schedules/{id}`         | V    | Read.            |
| `PATCH`  | `/v1/scan-schedules/{id}`         | O    | Update fields.   |
| `PATCH`  | `/v1/scan-schedules/{id}/enabled` | O    | Toggle.          |
| `POST`   | `/v1/scan-schedules/{id}/run`     | O    | Trigger now.     |
| `DELETE` | `/v1/scan-schedules/{id}`         | O    | Delete.          |

## Hosts

| Method | Path                                              | Role | Purpose                                                                                                                                                                                                             |
| ------ | ------------------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`  | `/v1/hosts/{ip}`                                  | V    | Host detail (includes `risk_score`, `probability`, `impact`, `confidence`, `risk_factors`, `risk_updated_at`).                                                                                                      |
| `GET`  | `/v1/hosts/{ip}/risk-explain`                     | V    | Persisted host score plus full probability×impact breakdown: per-channel `p_i` contributions, per-component impact weights, confidence sub-meters. See [Attack-Surface Score](../concepts/attack-surface-score.md). |
| `GET`  | `/v1/hosts/{ip}/related`                          | V    | Related hosts (cert / JARM / favicon); paginated via `page`, `limit` (default 10, max 100).                                                                                                                         |
| `GET`  | `/v1/hosts/{ip}/timeline`                         | V    | Service change events for the host.                                                                                                                                                                                 |
| `GET`  | `/v1/hosts/{ip}/services/{service_id}/screenshot` | V    | JPEG thumbnail rendered from the HTTP service. 404 until the background worker finishes.                                                                                                                            |
| `POST` | `/v1/hosts/{ip}/rtsp-snapshot`                    | V    | RTSP single-frame capture (gated).                                                                                                                                                                                  |
| `POST` | `/v1/hosts/{ip}/onvif-command`                    | V    | ONVIF command (gated).                                                                                                                                                                                              |
| `POST` | `/v1/hosts/{ip}/onvif-rtsp-snapshot`              | V    | ONVIF-assisted RTSP capture.                                                                                                                                                                                        |
| `POST` | `/v1/hosts/{ip}/onvif-lab-credential-probe`       | A    | Lab-only default-credential probe.                                                                                                                                                                                  |

## Search

| Method | Path         | Role | Purpose                                                                                                                         |
| ------ | ------------ | ---- | ------------------------------------------------------------------------------------------------------------------------------- |
| `GET`  | `/v1/search` | V    | Run a query. `format=csv` for CSV. Supports pivot filters: `jarm`, `ja3s`, `ja4s`, `favicon_hash`, `body_sha256`, `http_title`. |

## Pivot

| Method | Path                       | Role | Purpose                                                                                                                                                                                                                                    |
| ------ | -------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET`  | `/v1/pivot/{kind}/{value}` | V    | Force-graph payload for shared artifacts. `kind`: `tls_fingerprint`, `jarm`, `ja3s`, `ja4s`, `favicon_hash`, `body_sha256`, `http_title`. Query `limit` (default 200, max 500). Response includes `truncated` when matches exceed the cap. |

## Saved searches

| Method   | Path                          | Role | Purpose               |
| -------- | ----------------------------- | ---- | --------------------- |
| `POST`   | `/v1/saved-searches`          | O    | Create.               |
| `GET`    | `/v1/saved-searches`          | V    | List.                 |
| `POST`   | `/v1/saved-searches/{id}/run` | V    | Execute stored query. |
| `DELETE` | `/v1/saved-searches/{id}`     | O    | Delete.               |

## Alerts

| Method   | Path                      | Role | Purpose                     |
| -------- | ------------------------- | ---- | --------------------------- |
| `POST`   | `/v1/alerts`              | O    | Create rule.                |
| `GET`    | `/v1/alerts`              | V    | List rules (paginated).     |
| `GET`    | `/v1/alerts/all`          | V    | List rules (no pagination). |
| `GET`    | `/v1/alerts/events`       | V    | List events.                |
| `PATCH`  | `/v1/alerts/{id}/enabled` | O    | Toggle.                     |
| `DELETE` | `/v1/alerts/{id}`         | O    | Delete.                     |

## Dashboard

| Method | Path                          | Role | Purpose                                                                                            |
| ------ | ----------------------------- | ---- | -------------------------------------------------------------------------------------------------- |
| `GET`  | `/v1/dashboard`               | V    | Summary tiles.                                                                                     |
| `GET`  | `/v1/dashboard/map`           | V    | Country → service count.                                                                           |
| `GET`  | `/v1/dashboard/top`           | V    | Top ports / protocols / risk factors.                                                              |
| `GET`  | `/v1/dashboard/trends`        | V    | 7-day time series.                                                                                 |
| `GET`  | `/v1/dashboard/risk`          | V    | Service and host risk histograms; top risky services and hosts (sorted by persisted `risk_score`). |
| `GET`  | `/v1/dashboard/scans/summary` | V    | Latest scans by status.                                                                            |

## CVE

| Method | Path                     | Role | Purpose                    |
| ------ | ------------------------ | ---- | -------------------------- |
| `GET`  | `/v1/cve/sync-status`    | V    | NVD sync state.            |
| `GET`  | `/v1/cves/{id}`          | V    | CVE detail.                |
| `GET`  | `/v1/services/{id}/cves` | V    | CVE matches for a service. |

## Users (admin)

| Method   | Path                      | Role | Purpose         |
| -------- | ------------------------- | ---- | --------------- |
| `POST`   | `/v1/users`               | A    | Create user.    |
| `GET`    | `/v1/users`               | A    | List users.     |
| `GET`    | `/v1/users/{id}`          | A    | Read user.      |
| `PATCH`  | `/v1/users/{id}/role`     | A    | Change role.    |
| `PATCH`  | `/v1/users/{id}/password` | A    | Reset password. |
| `PATCH`  | `/v1/users/{id}/active`   | A    | Toggle active.  |
| `DELETE` | `/v1/users/{id}`          | A    | Delete.         |

## Audit (admin)

| Method | Path        | Role | Purpose              |
| ------ | ----------- | ---- | -------------------- |
| `GET`  | `/v1/audit` | A    | Query the audit log. |

## Attack-surface risk

| Method   | Path                                  | Role | Purpose                                                                                                                         |
| -------- | ------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------- |
| `GET`    | `/v1/hosts/{ip}/risk-history`         | V    | Score timeline from `uv_host_risk_snapshot`. See [Risk Explain](risk-explain.md).                                               |
| `GET`    | `/v1/hosts/{ip}/risk-recommendations` | V    | Read-only remediation recommendations for the host (regenerated on each scan). See [Remediation](../admin/remediation.md).      |
| `GET`    | `/v1/services/{id}/risk-explain`      | V    | Per-service probability channel breakdown.                                                                                      |
| `GET`    | `/v1/risk/policy`                     | V    | Read the current scoring policy (`uv_risk_policy`). See [Risk Policies](../concepts/risk-policies.md).                          |
| `PATCH`  | `/v1/risk/policy`                     | A    | Overwrite the scoring policy.                                                                                                   |
| `GET`    | `/v1/attack-paths/{ip}`               | V    | Host centrality + relation edges + `hosts[]` ID→IP references for graph nodes. See [Attack Paths](../concepts/attack-paths.md). |

## WebSocket

| Method        | Path     | Role                            | Purpose                                                                                                 |
| ------------- | -------- | ------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `GET` upgrade | `/v1/ws` | V (`REALTIME_WS_ALLOWED_ROLES`) | Realtime events. Streams `scan.status`, `alert.fired`, and `risk.event`. See [WebSocket](websocket.md). |

## Reminder

When you add a new endpoint, append a row here in the same commit. The
[`Documentation (Mandatory)`](#) rule in `CLAUDE.md` enforces it.
