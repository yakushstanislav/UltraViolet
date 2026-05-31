# Security Policy

## Supported versions

Security fixes are provided for the **latest release tag** and the **`main` branch**.
Older tags are not maintained unless noted in a release advisory.

| Version | Supported |
|---------|-----------|
| Latest `v*` release | Yes |
| `main` | Yes |
| Older tags | No |

## Reporting a vulnerability

If you believe you have found a **security vulnerability in UltraViolet itself**
(the API, scanner worker, authentication, authorization, or default deployment
configuration), please report it privately.

**Do not** open a public GitHub issue for exploitable security bugs.

| Channel | Contact |
|---------|---------|
| GitHub | [Private vulnerability report](https://github.com/yakushstanislav/UltraViolet/security/advisories/new) |
| Subject | `[UltraViolet Security]` short summary |

Include, where possible:

- Affected component (`uv-api`, `uv-scanner`, frontend, compose, etc.)
- Version or commit hash
- Steps to reproduce
- Impact assessment (confidentiality, integrity, availability)
- Proof of concept (minimal; no destructive payloads)

We aim to acknowledge reports within **5 business days** and will work with you
on a coordinated disclosure timeline. Please allow reasonable time to develop
and ship a fix before public disclosure.

## What this policy does **not** cover

The following are **out of scope** for this security program:

- **Misuse of the scanner** — scanning networks without authorization, denial
  of service caused by operator misconfiguration, or abuse of deployed
  instances you do not operate.
- **Findings on third-party targets** — vulnerabilities in hosts discovered
  *by* UltraViolet during a scan (report those to the asset owner or standard
  vendor channels).
- **CVE matches** — UltraViolet correlates services with public CVE data; it
  does not verify exploitability on your targets.

Operators are responsible for lawful, authorized use. See
[Responsible scanning](service-documentation-frontend/docs/security/responsible-scanning.md)
and the [production security checklist](service-documentation-frontend/docs/security/checklist.md).

## Secure deployment reminders

Before exposing an instance to untrusted networks:

1. Set `APP_ENV=production` and rotate bootstrap credentials.
2. Restrict `SCAN_ALLOWED_CIDRS` to authorized ranges.
3. Place HTTPS termination on a reverse proxy; bind API ports to loopback where possible.
4. Keep `ONVIF_LAB_CREDENTIAL_PROBE_ENABLED=false` outside lab environments.
5. Store secrets under `service-env/secrets/`, never in git.

## Preferred disclosure

We support **coordinated disclosure**. We ask reporters not to publish exploit
details until a fix is available, except where the issue is already public or
actively exploited in the wild.

Thank you for helping keep UltraViolet and its users safe.
