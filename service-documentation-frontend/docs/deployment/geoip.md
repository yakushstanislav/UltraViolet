# GeoIP

UltraViolet enriches every host with country, city, latitude/longitude,
ASN, and ASN organisation from MaxMind-format MMDB files. Both
`uv-scanner` (host enrichment + country-strategy execution) and
`uv-api` (country-strategy validation at `POST /v1/scans`) look for
two files:

- `ip-to-country.mmdb` — country + city + lat/lon.
- `ip-to-asn.mmdb` — ASN number + organisation.

Without the country MMDB, host GeoIP columns stay empty and
**country-strategy scans are rejected** at the API with
`scan_country_geoip_required`. Other scan modes keep working.

## Where the files live

The scanner and API search, in order:

1. `GEOIP_CITY_PATH` and `GEOIP_ASN_PATH` if set in `.env`.
2. `./geoip/ip-to-country.mmdb` and `./geoip/ip-to-asn.mmdb`
   relative to the working directory.
3. `/geoip/ip-to-country.mmdb` and `/geoip/ip-to-asn.mmdb` —
   the bind-mount path used in the shipping `docker-compose.yml`
   (mounted into both `uv-api` and `uv-scanner`).

If both files are absent at all three locations, the scanner logs a
one-time warning at boot:

```
geoip: no MMDB found at /geoip; country/asn enrichment disabled
```

`uv-api` logs `No GeoIP country database configured; country-strategy
scans will be rejected` and rejects country-strategy create requests.

## Provider — IPLocate

The default install uses the free [IPLocate](https://iplocate.io) MMDB
distributions. They are MaxMind-format-compatible.

`service-env/geoip/download-iplocate-mmdb.sh` downloads both files into
`service-env/geoip/`. The script is idempotent — it only re-downloads
when the upstream `Last-Modified` is newer than the local file.

```bash
cd service-env
./geoip/download-iplocate-mmdb.sh
ls geoip/
# ip-to-asn.mmdb
# ip-to-country.mmdb
```

`make geoip-download` (from repo root) is a convenience wrapper.

## Provider — MaxMind GeoLite2 / GeoIP2

If you have a MaxMind account, drop the official MMDB files into
`service-env/geoip/`:

```
service-env/geoip/ip-to-country.mmdb   # rename from GeoLite2-City.mmdb
service-env/geoip/ip-to-asn.mmdb       # rename from GeoLite2-ASN.mmdb
```

Restart `uv-scanner` after a download so enrichment picks up the new
MMDB. Restart `uv-api` too if you rely on country-strategy scans —
the API builds its prefix index at boot.

`uv-api` does not perform per-host GeoIP lookups; it only loads the
country MMDB to validate country-strategy scan requests.

## Scheduled refresh

GeoIP data drifts. Refresh monthly via cron:

```bash
# /etc/cron.d/ultraviolet-geoip
0 4 1 * * root cd /opt/ultraviolet/service-env && ./scripts/geoip-refresh.sh >> /var/log/uv-geoip.log 2>&1
```

`geoip-refresh.sh` runs the downloader and then restarts the scanner
so the new MMDB is loaded into memory. Scans that were running during
the restart are reclaimed automatically — see
[Scan Lifecycle](/concepts/scan-lifecycle).

## Hot-reloading

The scanner reads the MMDBs once at start-up and holds them in
memory. There is no inotify watcher — refreshing the file without a
restart leaves the in-memory copy stale. Restart `uv-scanner` after
every download (and `uv-api` when country-strategy scans must work).

## Verifying the data

Use the dashboard or the API to confirm country codes are populated:

```bash
curl -s -H "authorization: bearer $TOKEN" \
  "http://localhost:8080/v1/dashboard/summary" | jq '.top_countries'
```

A populated database with empty `country_code` everywhere is a sign
the MMDBs are not being loaded — check the scanner log for the
"no MMDB found" warning, and double-check `GEOIP_*_PATH` /
bind-mount paths.

## Air-gapped installs

The offline-full archive (`ultraviolet-vX.Y.Z-offline-full.tar.gz`)
includes both MMDBs in `geoip/`. `install.sh` detects them and points
`GEOIP_*_PATH` at the unpacked directory automatically. For refreshes
on an air-gapped host, manually copy fresh MMDBs into the same
location and run the equivalent of `geoip-refresh.sh` (which is just
`docker compose restart uv-scanner`).
