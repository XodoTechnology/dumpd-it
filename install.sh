#!/usr/bin/env bash
#
# dumpd installer for Debian 13 (trixie)
#   - installs Docker CE + compose plugin (official repo)
#   - installs dumpd to $INSTALL_DIR, generates .env + docker-compose.yml
#   - builds and starts the service
#
# Usage:
#   git clone <repo> && cd dumpd-it && sudo bash install.sh
#   or edit the CONFIG block below / export vars first.
#
set -euo pipefail

############################### CONFIG #####################################
# Edit these (or export them before running). Anything commented is optional.

INSTALL_DIR="${INSTALL_DIR:-/opt/dumpd}"

# IPs/CIDRs allowed to UPLOAD (downloads are always open). Comma-separated.
# Leave empty to be prompted (defaults to this SSH session's source IP).
UPLOAD_ALLOW="${UPLOAD_ALLOW:-}"

# --- Plain HTTP mode ------------------------------------------------------
HTTP_PORT="${HTTP_PORT:-8080}"        # host port when running without TLS

# --- Built-in TLS (auto Let's Encrypt). Uncomment + set DOMAIN ------------
# DOMAIN="files.example.com"          # comma-separated list ok
# ACME_EMAIL="you@example.com"        # optional, expiry notices
# ACME_STAGING="true"                 # use while testing to avoid rate limits
# SELF_SIGNED="true"                  # generate own cert instead of ACME
DOMAIN="${DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
ACME_STAGING="${ACME_STAGING:-false}"
SELF_SIGNED="${SELF_SIGNED:-false}"

# --- Optional knobs --------------------------------------------------------
# UNLOCK_KEY="s3cret"                 # allows unlimited upload size via ?key=
UNLOCK_KEY="${UNLOCK_KEY:-}"
MAX_UPLOAD_MB="${MAX_UPLOAD_MB:-10240}"
TTL="${TTL:-168h}"                    # rolling expiry, renewed on access
# BASE_URL="https://files.example.com"  # override generated URLs
BASE_URL="${BASE_URL:-}"
# BEHIND_PROXY="true"                 # if TLS terminated at a reverse proxy
BEHIND_PROXY="${BEHIND_PROXY:-false}"

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

# .env — consumed by docker compose (env_file) and used for port templating
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

# compose: port layout depends on TLS mode
if [[ -n "$DOMAIN" || "$SELF_SIGNED" == "true" ]]; then
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
    if [[ -n "$DOMAIN" || "$SELF_SIGNED" == "true" ]]; then
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
  upload:   curl https://$DOMAIN -T file.tar.gz     (from $UPLOAD_ALLOW)
  download: open the returned URL                   (any IP)
  first TLS handshake may take ~30s while the cert is issued.
MSG
else
    host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    cat <<MSG
  upload:   curl http://$host_ip:$HTTP_PORT -T file.tar.gz   (from $UPLOAD_ALLOW)
  download: open the returned URL                            (any IP)
MSG
fi
cat <<MSG

  config:   $INSTALL_DIR/.env   (edit, then: cd $INSTALL_DIR && docker compose up -d)
  logs:     cd $INSTALL_DIR && docker compose logs -f
  update:   re-run this script from the repo dir
MSG
