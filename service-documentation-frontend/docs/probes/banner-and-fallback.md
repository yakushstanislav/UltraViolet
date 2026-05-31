# Banner & Fallback

When no protocol-specific probe matches, the scanner falls back to a
generic TCP banner grab. This page explains what that looks like and
what ends up in the service record.

## Generic banner grab

The generic banner probe opens a TCP connection, waits up to
`PROBE_TIMEOUT` for the server to send greeting bytes, and reads up to
`PROBE_MAX_BODY_BYTES`. If the server stays silent, the probe sends a
single `\r\n` and reads again.

The captured banner is stored as raw text (sanitised to UTF-8) along
with its SHA-256 hash. The hash is used by the delta engine — two scans
of the same service produce a `changed` event whenever the hash
differs, regardless of cosmetic whitespace. A full-text search vector
is also built from the banner text, enabling keyword search.

## Fallback dispatch

Fallback fires when:

- No port-mapped probe is registered for the port.
- A port-mapped probe ran but decided the service is not what it
  expected.
- The generic banner returned data but no fingerprint rule matched.

Fallback then pattern-matches the first 64 bytes to make a best-effort
guess:

| First-byte pattern | Guess |
|---|---|
| `SSH-2.0-…` | OpenSSH (or vendor extracted from the suffix) |
| `220 …` | SMTP (port 25/465/587) or FTP (port 21) |
| `+OK …` | POP3 |
| `* OK …` | IMAP |
| `HTTP/1.` | dispatched to HTTP probe (rare — should have been caught earlier) |
| `<? xml` / `<soap:` | hints that an ONVIF/UPnP probe should re-run |

Fingerprints produced by fallback always have **low confidence**. The
CVE matcher applies a stricter threshold to low-confidence rows — it
requires a version string, not just a product name, before claiming a
match.

## Service fingerprints

After probing (whether by a protocol probe or fallback), the service
record gets a fingerprint with:

- **Product** — canonicalised vendor/product name (e.g. `nginx`,
  `OpenSSH`, `Mosquitto`).
- **Version** — best-effort version string. Empty when the protocol
  doesn't expose one.
- **Confidence** — `high` (exact match), `medium` (heuristic), `low`
  (banner-only).
- **Components** — side-channel metadata: SSH algorithms, TLS cipher
  suites, HTTP frameworks.
- **Auth required** — set when the probe got an explicit
  "authentication required" response.

## Examples

1. **Port 9999, custom RPC**. No probe registered. Fallback captures
   the banner (`"PROD v1.4.2 ready"`), guesses `product = "PROD"`,
   `confidence = low`. The CVE matcher does not attempt a join without
   a trustworthy version.

2. **Port 22 with a non-OpenSSH server**. The SSH probe runs, sees
   `SSH-2.0-CustomBox_3.1`, captures the algorithms list, and writes a
   `high`-confidence fingerprint of `product = "CustomBox"`,
   `version = "3.1"`. Fallback does not fire.

3. **Port 25, TLS-wrapped**. The SMTP probe times out on the cleartext
   greeting because the service requires STARTTLS-first. Fallback
   captures the empty banner; the TLS probe (which runs in parallel)
   succeeds and records the certificate. The host detail view shows
   the TLS data; the SMTP fingerprint stays empty.
