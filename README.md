# dumpd

A tiny, secure, curl-friendly file drop — like bashupload, but self-hosted.

- **Upload from allowlisted IPs only** (`UPLOAD_ALLOW` CIDRs); downloads are open to anyone with the link.
- **Built-in TLS**: set `DOMAIN` and it fetches + auto-renews a Let's Encrypt cert itself. Or `SELF_SIGNED=true`, or bring your own `CERT_FILE`/`KEY_FILE`.
- **Compression at rest**: uploads are gzip'd on write unless already a compressed format. Clients that send `Accept-Encoding: gzip` get the compressed bytes straight off disk; everyone else gets transparent decompression.
- **Rolling 7-day TTL**: every download resets the expiry clock. Files untouched for the TTL are deleted by a background sweeper (which also reclaims orphaned blobs and aborted-upload temp files).
- **10 GB default cap**, bypassable per-request with an `UNLOCK_KEY`. A free-disk floor (`MIN_FREE_MB`) refuses uploads when the volume runs low.
- **Domain-agnostic**: URLs come from `Host`/`X-Forwarded-Proto` (canonicalized to `DOMAIN` when set), or set `BASE_URL`.
- **Download metadata**: `Accept: application/json` on a download URL returns size, sha256, expiry and hit count instead of bytes. Responses carry a weak `ETag` (the sha256) with `If-None-Match` → 304 support, plus `nosniff`, `Content-Disposition: attachment`, CSP `sandbox`, and HSTS on TLS.

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
curl http://localhost:8080 -T backup.tar.gz http://localhost:8080/backup.tar.gz
# -> http://localhost:8080/d/AbCdEfGhIjK/backup.tar.gz
```

The filename comes from (in order): `?filename=`, the URL path basename, or the
multipart part filename (`-F file=@...`). A bare `curl -T file http://host`
saves as `file` — put the name in the path or use `-F`/`?filename=` to keep it.

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
curl https://files.example.com/backup.tar.gz -T backup.tar.gz   # upload, allowed IP only
curl -O https://files.example.com/d/<id>/backup.tar.gz           # download, anyone
curl -H 'Accept: application/json' https://files.example.com/d/<id>/backup.tar.gz
# -> {"filename":..., "size":..., "sha256":..., "downloads":..., "expires":...}
```

## Unlock key (unlimited upload size)

```sh
UNLOCK_KEY=s3cret docker compose up -d
curl 'https://files.example.com/?key=s3cret' -T hugefile.img
# or: curl -H 'X-Upload-Key: s3cret' ...
```

Without the key, `MAX_UPLOAD_MB` applies (default 10240 = 10 GB). Prefer
`[A-Za-z0-9._~-]` for the key — exotic characters can be mangled by `.env`
parsing.

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
| `BEHIND_PROXY`   | `false`   | Trust `X-Forwarded-For`/`X-Real-IP`/`X-Forwarded-Proto`. |
| `PROXY_HOPS`     | `1`       | Trusted proxies appending XFF; client IP taken this many entries from the right. |
| `BASE_URL`       | auto      | Public base URL override.                          |
| `MAX_UPLOAD_MB`  | `10240`   | Max upload size (0 not supported; use UNLOCK_KEY). |
| `MIN_FREE_MB`    | `1024`    | Refuse uploads when free disk drops below this (0=off). |
| `UNLOCK_KEY`     | —         | Secret enabling unlimited size via `?key=`/`X-Upload-Key`. |
| `TTL`            | `168h`    | Lifetime, renewed on every access (Go duration).   |
| `SWEEP_INTERVAL` | `10m`     | Expiry/orphan/tmp purge interval.                  |
| `DATA_DIR`       | `/data`   | Storage (blobs, meta, certs) — volume-mount it.    |
| `PORT`           | `8080`    | Host port for the plain-HTTP listener (compose only). |

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
  With multiple chained proxies set `PROXY_HOPS` to the number of proxies
  between the client and dumpd — the client IP is read that many entries from
  the **right** of `X-Forwarded-For`, so client-supplied entries on the left
  can't spoof the allowlist.
- **Built-in TLS mode**: the container must be reachable on **both** 80 and 443
  publicly (443 for tls-alpn-01, 80 for http-01 + redirects). Plain-HTTP
  requests get a `308` redirect, so `curl -T` uploads survive the hop.
- When `BEHIND_PROXY=true`, ensure only the proxy can reach dumpd's port —
  the rightmost XFF entries are trusted blindly.
- The container runs hardened: `cap_drop ALL`, `no-new-privileges`,
  `read_only` rootfs, `/tmp` tmpfs. Binding :80/:443 relies on the compose
  sysctl `net.ipv4.ip_unprivileged_port_start=0` — keep it if you write your
  own compose file (a bare `docker run` needs
  `--sysctl net.ipv4.ip_unprivileged_port_start=0`).

## Security notes

- Uploads denied unless source IP matches `UPLOAD_ALLOW`; with
  `BEHIND_PROXY=false` the TCP peer is used and cannot be spoofed.
- Download IDs are 64-bit random tokens; delete keys 192-bit. Both secrets
  (plus `UNLOCK_KEY`) are compared as SHA-256 digests in constant time, so
  neither value nor length leaks through timing.
- Files always served `Content-Disposition: attachment` + `nosniff` + CSP
  `sandbox`, so uploaded HTML/JS can't execute in a visitor's browser.
- Generated URLs are canonicalized: with `DOMAIN` set, a spoofed `Host`
  header can't poison download/delete links.
- `curl -i` on upload reveals an `X-Delete-Url`; `Accept: application/json`
  returns url, delete_url, sha256, expiry. Prefer the `X-Upload-Key` /
  `X-Delete-Key` headers over `?key=` so secrets stay out of URLs and logs.
- The sweeper deletes expired/corrupt records, reclaims blobs with no meta
  (after a 10-minute grace), and removes temp files older than 24h. Transient
  read errors never delete live files.
