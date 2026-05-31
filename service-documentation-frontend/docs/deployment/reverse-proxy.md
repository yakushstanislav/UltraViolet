# Reverse Proxy

In production, run UltraViolet behind a TLS-terminating reverse proxy.
The shipping `service-frontend` nginx already proxies `/api/` and
`/realtime/` to `uv-api`, so the outer proxy only needs to terminate
TLS and forward `:443 → :3000`.

A complete annotated example is in
`service-env/examples/nginx-tls.conf` — Let's Encrypt, HSTS, WebSocket
upgrade, secure headers. This page covers the integration points; copy
the example for the full config.

## Minimal nginx in front of UltraViolet

```nginx
upstream uv_frontend {
    server 127.0.0.1:3000;
}

server {
    listen 443 ssl http2;
    server_name uv.example.com;

    ssl_certificate     /etc/letsencrypt/live/uv.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/uv.example.com/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "no-referrer" always;

    # SPA + REST + WS — single origin
    location / {
        proxy_pass         http://uv_frontend;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # WebSocket upgrade for /realtime/*
        proxy_http_version 1.1;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        "upgrade";
        proxy_read_timeout 3600s;
    }
}

server {
    listen 80;
    server_name uv.example.com;
    return 301 https://$host$request_uri;
}
```

The single `location /` block works because `service-frontend` nginx
already discriminates between the SPA, `/api`, and `/realtime` —
treating UltraViolet as one origin is correct.

## Binding the frontend to localhost

Once the outer proxy is set up, expose `service-frontend` only on
loopback so attackers cannot bypass TLS:

```yaml
# docker-compose.override.yml
services:
  service-frontend:
    ports:
      - "127.0.0.1:3000:8080"
```

Apply the same to `uv-api` if you don't want its REST/WS/metrics ports
on the public interface:

```yaml
  uv-api:
    ports:
      - "127.0.0.1:8080:8080"
      - "127.0.0.1:8081:8081"
      - "127.0.0.1:9090:9090"
```

## Environment changes

```bash
CORS_ALLOWED_ORIGINS=https://uv.example.com
AUDIT_TRUST_PROXY_HEADERS=true
```

| Env | Why |
|---|---|
| `CORS_ALLOWED_ORIGINS` | Match the public origin; reject everything else. |
| `AUDIT_TRUST_PROXY_HEADERS` | Tell the audit + rate-limit middleware to trust X-Forwarded-For. |

The audit middleware parses XFF right-to-left and picks the first
non-private hop — see [Audit Log](/admin/audit) for the parsing rules.

## WebSocket considerations

WebSocket connections survive long enough to hit default proxy timeouts.
Two things to set:

1. `proxy_read_timeout 3600s` — or longer. Otherwise nginx drops the
   connection after 60 s of silence and the client reconnects in a
   loop.
2. `Upgrade` + `Connection` headers as in the example. Without them,
   nginx does HTTP/1.1 keep-alive and the upgrade handshake fails.

The SPA reconnects automatically (exponential backoff 1 s → 30 s), but
constant reconnects flood the audit log and the metrics.

## TLS termination at the docker layer

If you prefer to terminate TLS inside the stack (Caddy, Traefik), add
the container to `docker-compose.override.yml` and route to
`service-frontend`. The same headers and timeouts apply.

## Sub-path deployment

`UV_BASE_PATH` lets you mount UltraViolet under a sub-path, e.g.
`https://intranet.example.com/ultraviolet/`. Set:

```bash
# .env
UV_BASE_PATH=/ultraviolet/
# Frontend build
VITE_BASE_PATH=/ultraviolet/
```

`service-frontend`'s `entrypoint.sh` renders `nginx.conf` with
`UV_BASE_PATH` at container start. The SPA's API/WS proxies become
`/ultraviolet/api/` and `/ultraviolet/realtime/`. Configure the outer
proxy to forward the sub-path verbatim.

## Static assets inside `service-frontend` nginx

The shipping frontend image serves the Vite `dist/` tree with:

- **`gzip_static`** for precompressed `.gz` siblings produced at build time
  (fallback `gzip on` for clients without a matching file).
- **Long-lived cache** (`Cache-Control: public, max-age=31536000, immutable`)
  for hashed files under `/assets/`.
- **`index.html` uncached** so SPA deploys pick up new chunk hashes immediately.

Route-level code splitting keeps the main `index-*.js` entry small; map
(Leaflet/cobe) and form libraries load only when their routes mount.
CI enforces a gzip budget on the entry chunk via
`npm run build:check-size` in `service-frontend`.

## Health checks at the LB

Point the load balancer at `/readyz` on `uv-api:8080`. It returns
`503` while migrations are running, so a rolling deploy that taps
`/readyz` will wait correctly.

For active/standby setups, also check `/livez` separately — `livez` is
a process-up signal that doesn't depend on Postgres.
