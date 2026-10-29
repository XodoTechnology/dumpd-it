# dumpd

A tiny, secure, curl-friendly file drop — like bashupload, but self-hosted.

- **Upload from allowlisted IPs only** (`UPLOAD_ALLOW` CIDRs); downloads are open to anyone with the link.
- **Built-in TLS**: set `DOMAIN` and it fetches + auto-renews a Let's Encrypt cert itself. Or `SELF_SIGNED=true`, or bring your own `CERT_FILE`/`KEY_FILE`.
- **Compression at rest**: uploads are gzip'd on write unless already a compressed format. Clients that send `Accept-Encoding: gzip` get the compressed bytes straight off disk; everyone else gets transparent decompression.
- **Rolling 7-day TTL**: every download resets the expiry clock. Files untouched for the TTL are deleted by a background sweeper.
- **10 GB default cap**, bypassable per-request with an `UNLOCK_KEY`.
- **Domain-agnostic**: URLs come from `Host`/`X-Forwarded-Proto`, or set `BASE_URL`.

## Quick start (Debian 13)

```sh
sudo bash install.sh
```

Installs Docker CE + compose plugin, asks for your **domain** (default path:
direct Let's Encrypt HTTPS on 80/443 — no proxy needed), your upload IP
(defaults to your current SSH source IP), deploys to `/opt/dumpd`, builds and
starts the service. No domain? It offers self-signed HTTPS on :443, else falls
back to plain HTTP on `HTTP_PORT` (8080). Config lives in the commented CONFIG
block at the top of `install.sh`, or in `/opt/dumpd/.env` afterwards.

## Quick start (manual)

```sh
# domain mode: point DNS here first
DOMAIN=files.example.com UPLOAD_ALLOW="1.2.3.4/32" docker compose up -d --build
# or plain http:
docker compose up -d --build
curl http://localhost:8080 -T backup.tar.gz
# -> http://localhost:8080/d/AbCdEfGhIjK/backup.tar.gz
```

## Quick start (own domain, auto HTTPS)

Point `files.example.com` A/AAAA at the host, then:

```sh
DOMAIN=files.example.com UPLOAD_ALLOW="1.2.3.4/32" docker compose up -d --build
```

with the 80/443 port mappings uncommented in `docker-compose.yml`. dumpd gets
the cert from Let's Encrypt on first request and renews it automatically
(cached in the data volume). Set `ACME_STAGING=true` while testing to avoid
rate limits.

```sh
curl https://files.example.com -T backup.tar.gz   # upload, allowed IP only
curl -O https://files.example.com/d/<id>/backup.tar.gz   # download, anyone
```

## Unlock key (unlimited upload size)

```sh
UNLOCK_KEY=s3cret docker compose up -d
curl 'https://files.example.com/?key=s3cret' -T hugefile.img
# or: curl -H 'X-Upload-Key: s3cret' ...
```

Without the key, `MAX_UPLOAD_MB` applies (default 10240 = 10 GB).

## Configuration (env)

| Var              | Default   | Meaning                                            |
|------------------|-----------|----------------------------------------------------|
| `UPLOAD_ALLOW`   | *(none)*  | IPs/CIDRs allowed to upload. Empty = deny all.     |
| `DOMAIN`         | —         | Enables ACME TLS for this domain (comma-sep list). |
| `TLS_ADDR`       | `:443`    | HTTPS listen address.                              |
| `ADDR`           | `:8080` / `:80` in TLS mode | HTTP listen addr (acme challenge + redirect); `off` to disable. |
| `ACME_EMAIL`     | —         | Optional contact for Let's Encrypt notices.        |
| `ACME_STAGING`   | `false`   | Use LE staging CA (testing, avoids rate limits).   |
| `SELF_SIGNED`    | `false`   | Generate a self-signed cert instead of ACME.       |
| `CERT_FILE`/`KEY_FILE` | —   | Manual TLS certs (override ACME).                  |
| `BEHIND_PROXY`   | `false`   | Trust `X-Forwarded-*` (TLS terminated at proxy).   |
| `BASE_URL`       | auto      | Public base URL override.                          |
| `MAX_UPLOAD_MB`  | `10240`   | Max upload size (0 not supported; use UNLOCK_KEY). |
| `UNLOCK_KEY`     | —         | Secret enabling unlimited size via `?key=`/`X-Upload-Key`. |
| `TTL`            | `168h`    | Lifetime, renewed on every access (Go duration).   |
| `SWEEP_INTERVAL` | `10m`     | Expired-file purge interval.                       |
| `DATA_DIR`       | `/data`   | Storage (blobs, meta, certs) — volume-mount it.    |

## Reinstalling / updating / wiping

```sh
sudo bash install.sh                      # re-run: updates code + rebuilds (data kept)
cd /opt/dumpd && docker compose down -v   # stop + delete stored files/certs
rm -rf /opt/dumpd                         # remove install entirely
```

Re-running `install.sh` regenerates `.env` from the CONFIG block / exported
vars — a copy of the previous one is saved as `.env.bak`.

## Deployment notes

- **Reverse proxy mode**: terminate TLS at nginx/caddy/traefik, keep
  `BEHIND_PROXY=true`. In nginx: `client_max_body_size 0;`
  `proxy_request_buffering off;` and pass `X-Forwarded-For`/`X-Forwarded-Proto`.
- **Built-in TLS mode**: the container must be reachable on **both** 80 and 443
  publicly (443 for tls-alpn-01, 80 for http-01 + redirects).
- When `BEHIND_PROXY=true`, ensure only the proxy can reach dumpd's port —
  otherwise `X-Forwarded-For` can be spoofed to bypass the upload allowlist.

## Security notes

- Uploads denied unless source IP matches `UPLOAD_ALLOW`; with
  `BEHIND_PROXY=false` the TCP peer is used and cannot be spoofed.
- Download IDs are 64-bit random tokens; delete keys 192-bit, compared in
  constant time (same for `UNLOCK_KEY`).
- Files always served `Content-Disposition: attachment` + `nosniff`, so
  uploaded HTML/JS can't execute in a visitor's browser.
- `curl -i` on upload reveals an `X-Delete-Url`; `Accept: application/json`
  returns url, delete_url, sha256, expiry.
