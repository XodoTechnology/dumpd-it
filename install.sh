#!/usr/bin/env bash
#
# dumpd installer for Debian 13 (trixie)
#   - installs Docker CE + compose plugin (official repo)
#   - domain-first: auto Let's Encrypt HTTPS on 80/443 (default)
#   - falls back to self-signed HTTPS or plain HTTP if no domain
#   - installs dumpd to $INSTALL_DIR, generates .env + docker-compose.yml
#
# Usage:
#   git clone <repo> && cd dumpd-it && sudo bash install.sh
#   or edit the CONFIG block below / export vars first.
#
set -euo pipefail

############################### CONFIG #####################################
# Edit these (or export them before running). Anything commented is optional.

INSTALL_DIR="${INSTALL_DIR:-/opt/dumpd}"

# Your domain — point its A/AAAA record at this server. Comma-separated ok.
# Set this and everything else (cert issuance, renewal, http->https redirect)
# is automatic. You'll be prompted if left empty.
DOMAIN="${DOMAIN:-}"
# ACME_EMAIL="you@example.com"        # optional, Let's Encrypt notices
ACME_EMAIL="${ACME_EMAIL:-}"
# ACME_STAGING="true"                 # use while testing to avoid rate limits
ACME_STAGING="${ACME_STAGING:-false}"
# SELF_SIGNED="true"                  # force self-signed cert (no ACME)
SELF_SIGNED="${SELF_SIGNED:-false}"

# IPs/CIDRs allowed to UPLOAD (downloads are always open). Comma-separated.
# Leave empty to be prompted (defaults to this SSH session's source IP).
UPLOAD_ALLOW="${UPLOAD_ALLOW:-}"

# --- Optional knobs --------------------------------------------------------
# UNLOCK_KEY="s3cret"                 # allows unlimited upload size via ?key=
UNLOCK_KEY="${UNLOCK_KEY:-}"
MAX_UPLOAD_MB="${MAX_UPLOAD_MB:-10240}"
TTL="${TTL:-168h}"                    # rolling expiry, renewed on access
# BASE_URL="https://files.example.com"  # override generated URLs (rarely needed)
BASE_URL="${BASE_URL:-}"
# BEHIND_PROXY="true"                 # only if you front dumpd with your own proxy
BEHIND_PROXY="${BEHIND_PROXY:-false}"
HTTP_PORT="${HTTP_PORT:-8080}"        # plain-HTTP fallback only (no domain, no TLS)

############################################################################

c() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo bash install.sh)"
. /etc/os-release 2>/dev/null || die "cannot detect OS"
[[ "${ID:-}" == "debian" ]] || warn "tested on Debian 13; detected '${ID:-unknown}' - continuing anyway"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/go.mod" && -f "$SCRIPT_DIR/Dockerfile" ]] \
    || die "run this script from the dumpd-it repo directory"

############################ domain / TLS mode #############################
if [[ -z "$DOMAIN" && "$SELF_SIGNED" != "true" && -t 0 ]]; then
    suggested="$(hostname -f 2>/dev/null || true)"
    [[ "$suggested" == *.* ]] || suggested=""
    read -rp "Domain for auto-HTTPS (blank to skip)${suggested:+ [$suggested]}: " ans
    DOMAIN="${ans:-$suggested}"
fi
if [[ -z "$DOMAIN" && "$SELF_SIGNED" != "true" && -t 0 ]]; then
    read -rp "No domain set - serve HTTPS with a self-signed cert on :443? [Y/n]: " ans
    case "${ans:-y}" in [Nn]*) ;; *) SELF_SIGNED="true";; esac
fi
TLS_MODE=""
[[ -n "$DOMAIN" || "$SELF_SIGNED" == "true" ]] && TLS_MODE=1

if [[ -n "$DOMAIN" ]]; then
    first_domain="${DOMAIN%%,*}"
    resolved="$(getent ahostsv4 "$first_domain" 2>/dev/null | awk 'NR==1{print $1}' || true)"
    mine="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ -z "$resolved" ]]; then
        warn "$first_domain does not resolve - cert issuance will FAIL until DNS is set"
    elif [[ -n "$mine" && "$resolved" != "$mine" ]]; then
        warn "$first_domain resolves to $resolved but this host appears to be $mine"
        warn "cert issuance will fail unless that host forwards 80/443 here"
    else
        c "DNS ok: $first_domain -> $resolved"
    fi
fi

if [[ -n "$TLS_MODE" ]] && ss -tln 2>/dev/null | grep -qE ':(80|443) '; then
    warn "something is already listening on 80/443 - cert issuance/redirect may fail:"
    ss -tlnp 2>/dev/null | grep -E ':(80|443) ' | sed 's/^/    /' >&2 || true
fi

########################## prompt: upload allowlist #########################
if [[ -z "$UPLOAD_ALLOW" ]]; then
    ssh_ip="$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')"
    [[ -n "$ssh_ip" ]] || ssh_ip="$(who -u 2>/dev/null | awk 'match($0,/\(([0-9.]+)\)/,m){print m[1]}' | head -1)"
    def="${ssh_ip:-127.0.0.1}"
    if [[ -t 0 ]]; then
        read -rp "IP(s)/CIDR(s) allowed to upload [${def}]: " ans
        UPLOAD_ALLOW="${ans:-$def}"
    else
        UPLOAD_ALLOW="$def"
        warn "non-interactive: defaulting UPLOAD_ALLOW=$UPLOAD_ALLOW"
    fi
fi
c "upload allowlist: $UPLOAD_ALLOW"

############################# install docker ###############################
if ! command -v docker >/dev/null 2>&1; then
    c "installing Docker CE (docker.com apt repo)"
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
    c "docker already installed ($(docker --version | cut -d' ' -f3 | tr -d ,))"
fi
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"
systemctl enable --now docker >/dev/null 2>&1 || true

############################## lay down files ##############################
c "installing app to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -f "$SCRIPT_DIR"/*.go "$SCRIPT_DIR"/go.mod "$SCRIPT_DIR"/go.sum \
      "$SCRIPT_DIR"/Dockerfile "$SCRIPT_DIR"/.dockerignore "$SCRIPT_DIR"/README.md \
      "$INSTALL_DIR"/ 2>/dev/null || true

# .env — passed to the container via env_file.
# Back up any existing one first in case it was hand-edited.
if [[ -f "$INSTALL_DIR/.env" ]] && ! cmp -s "$INSTALL_DIR/.env" /dev/null 2>/dev/null; then
    cp -f "$INSTALL_DIR/.env" "$INSTALL_DIR/.env.bak"
fi
{
    echo "UPLOAD_ALLOW=$UPLOAD_ALLOW"
    echo "BEHIND_PROXY=$BEHIND_PROXY"
    echo "MAX_UPLOAD_MB=$MAX_UPLOAD_MB"
    echo "TTL=$TTL"
    [[ -n "$BASE_URL" ]]    && echo "BASE_URL=$BASE_URL"
    [[ -n "$UNLOCK_KEY" ]]  && echo "UNLOCK_KEY=$UNLOCK_KEY"
    if [[ -n "$DOMAIN" ]]; then
        echo "DOMAIN=$DOMAIN"
        echo "ACME_STAGING=$ACME_STAGING"
        [[ -n "$ACME_EMAIL" ]] && echo "ACME_EMAIL=$ACME_EMAIL"
    fi
    [[ "$SELF_SIGNED" == "true" ]] && echo "SELF_SIGNED=true"
} > "$INSTALL_DIR/.env"
chmod 600 "$INSTALL_DIR/.env"

# compose: domain/self-signed -> serve 80+443 directly; else plain http port
if [[ -n "$TLS_MODE" ]]; then
    PORTS=$'      - "80:80"\n      - "443:443"'
else
    PORTS="      - \"${HTTP_PORT}:8080\""
fi
cat > "$INSTALL_DIR/docker-compose.yml" <<YAML
services:
  dumpd:
    build: .
    restart: unless-stopped
    ports:
$PORTS
    sysctls:
      - net.ipv4.ip_unprivileged_port_start=0
    env_file: .env
    volumes:
      - dumpd-data:/data
volumes:
  dumpd-data:
YAML

############################### firewall ###################################
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
    c "ufw detected - opening required ports"
    if [[ -n "$TLS_MODE" ]]; then
        ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
    else
        ufw allow "$HTTP_PORT"/tcp >/dev/null
    fi
fi

############################### build + up #################################
cd "$INSTALL_DIR"
c "building image"
docker compose build -q
c "starting"
docker compose up -d

sleep 1
echo
c "done. service status:"
docker compose ps --format '  {{.Name}}  {{.Status}}  {{.Ports}}' || docker compose ps
echo
if [[ -n "$DOMAIN" ]]; then
    cat <<MSG
  upload:   curl https://${DOMAIN%%,*} -T file.tar.gz      (from $UPLOAD_ALLOW)
  download: open the returned URL                          (any IP)
  the first https request may take ~30s while the cert is issued.
MSG
elif [[ "$SELF_SIGNED" == "true" ]]; then
    host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    cat <<MSG
  upload:   curl -k https://$host_ip -T file.tar.gz        (from $UPLOAD_ALLOW)
  download: curl -kO <returned URL>                        (any IP)
  self-signed cert: browsers will warn; use -k with curl.
MSG
else
    host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    cat <<MSG
  upload:   curl http://$host_ip:$HTTP_PORT -T file.tar.gz (from $UPLOAD_ALLOW)
  download: open the returned URL                          (any IP)
MSG
fi
cat <<MSG

  config:   $INSTALL_DIR/.env   (edit, then: cd $INSTALL_DIR && docker compose up -d)
  logs:     cd $INSTALL_DIR && docker compose logs -f
  update:   re-run this script from the repo dir
MSG
