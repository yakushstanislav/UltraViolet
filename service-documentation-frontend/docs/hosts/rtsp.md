# RTSP Snapshots

The RTSP snapshot endpoint captures a single JPEG frame from a live RTSP
stream and streams it back through the API. It is the
"is-this-camera-actually-pointed-at-something" sanity check during
investigations.

## Direct RTSP snapshot

`POST /v1/hosts/{ip}/rtsp-snapshot`:

```bash
curl -s -X POST "http://localhost:8080/v1/hosts/198.51.100.42/rtsp-snapshot" \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "port":     554,
    "path":     "/Streaming/Channels/101",
    "username": "viewer",
    "password": "viewer"
  }' \
  -o frame.jpg
```

| Field | Notes |
|---|---|
| `port` | TCP port; default `554`. |
| `path` | Stream path. Most cameras expose at least one anonymous path. |
| `username`, `password` | Optional. Empty = anonymous. |

The response body is a JPEG when the capture succeeds. Errors come back
as a JSON object with `code` and `message`.

## ONVIF-assisted snapshot

`POST /v1/hosts/{ip}/onvif-rtsp-snapshot` lets the server discover the
RTSP URI for you via ONVIF `GetProfiles` + `GetStreamUri`, then captures
the frame:

```bash
curl -s -X POST "http://localhost:8080/v1/hosts/198.51.100.42/onvif-rtsp-snapshot" \
  -H "authorization: bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "port":     80,
    "username": "admin",
    "password": "12345"
  }' \
  -o frame.jpg
```

This is the recommended path — it handles vendors that put the stream
on a non-standard path. The endpoint requires `ONVIF_COMMAND_ENABLED`
and `ONVIF_RTSP_SNAPSHOT_ENABLED` to be `true`.

## How the capture works

UltraViolet shells out to `ffmpeg`. The default invocation is roughly:

```bash
ffmpeg -nostdin -y \
  -rtsp_transport tcp \
  -i 'rtsp://<user>:<pass>@<ip>:<port><path>' \
  -frames:v 1 -f image2 -update 1 \
  -timeout $RTSP_SNAPSHOT_TIMEOUT \
  /tmp/<uuid>.jpg
```

The server reads the resulting JPEG, streams it to the client, and
deletes the temp file.

## Configuration

| Env | Default | Purpose |
|---|---|---|
| `RTSP_SNAPSHOT_ENABLED` | `true` | Master switch. `false` returns `503`. |
| `RTSP_SNAPSHOT_FFMPEG` | `ffmpeg` | Binary path (or full path). |
| `RTSP_SNAPSHOT_TIMEOUT` | `12s` | ffmpeg wall-clock cap. |
| `RTSP_SNAPSHOT_MAX_CONCURRENT` | `4` | Concurrent captures per `uv-api` process. |
| `ONVIF_RTSP_SNAPSHOT_ENABLED` | `true` | Master switch for the ONVIF-assisted variant. |

`ffmpeg` must be available in the container image. The default
`uv-api` image bundles it; if you build a custom image, install
`ffmpeg` in the final stage.

## Failure modes

| Symptom | Likely cause |
|---|---|
| `503 rtsp_disabled` | `RTSP_SNAPSHOT_ENABLED=false`. |
| `504 capture_timeout` | ffmpeg did not produce a frame inside the budget — wrong path, NAT issue, or stream stalled. |
| `401 unauthorized_rtsp` | Credentials wrong, or the stream requires Digest auth and the client sent Basic. |
| `400 invalid_uri` | The constructed RTSP URI failed parsing — usually `path` did not start with `/`. |

## Security and audit

Every capture is logged in `uv_audit_event` with the requesting user,
the target IP/port/path, the status, and the response size. Sending
captures to other operators is fine (the JPEG is stored client-side
only, not in Postgres). If you want to retain frames, save them outside
UltraViolet.

The capture pipeline does not store credentials. They live for the
duration of one ffmpeg invocation and are discarded.

## When the endpoint is the wrong tool

- For continuous viewing — use a dedicated RTSP client; UltraViolet is
  built for one-shot captures, not live streams.
- For brute-forcing credentials — disallowed; use the
  [ONVIF lab credential probe](/hosts/onvif#lab-credential-probe-admin-only-lab-only)
  in a lab environment if you have admin role.
