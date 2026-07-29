#!/usr/bin/env bash
sed -i 's/\r$//' "$0" 2>/dev/null || true
set -euo pipefail

# =========================
# Cloudflare + Nginx + Static + Backend Proxy Installer (A-Z)
# BEST edition:
# - Multi-domain support via domains file
# - Wildcard support per domain: domain + *.domain
# - Optional explicit wildcard hostname entries (e.g. *.r.af.d.example.com)
# - Same backend for all domains
# - Cloudflare Origin CA cert via API (no manual paste)
# - Idempotent re-runs (re-issue cert only if domains changed or cert missing/expiring)
# - Locks firewall to Cloudflare only (UFW on Debian/Ubuntu)
# - Interactive menu plus helper commands: install/uninstall/status/diagnose/apply
# =========================

# ====== EDIT THESE (MINIMUM) ======
BACKEND_URL="https://oldserver-beta-v.up.railway.app"
CF_API_TOKEN="cfut_4WqmxX8yrUfGUJYlkHVJmgTxZTHhRU6x64Xpxpqpf4e39b9a"   # Prefer env var: export CF_API_TOKEN="..."
# =================================

# Optional: where to store/read domains from
DOMAINS_FILE_DEFAULT="/etc/cf-vps/domains.txt"

# Optional fallback domains if no file exists yet
DOMAINS_FALLBACK=("example.com")

# Behavior
ENABLE_WILDCARDS=1             # 1 = include *.domain for each domain
INCLUDE_WWW=0                  # 1 = also include www.domain explicitly (not required if wildcard enabled)
CERT_RENEW_IF_DAYS_LEFT_LT=30  # re-issue cert if expires in < N days

# Paths
STATE_DIR="/etc/cf-vps"
CF_SSL_DIR="/etc/ssl/cloudflare"
CERT_PATH="${CF_SSL_DIR}/cert.pem"
KEY_PATH="${CF_SSL_DIR}/key.pem"
CSR_PATH="${CF_SSL_DIR}/origin.csr"
HOSTNAMES_HASH_PATH="${CF_SSL_DIR}/hostnames.sha256"
FORWARDER_SECRET_PATH="${STATE_DIR}/forwarder_secret"
NGINX_SITE_CONF="/etc/nginx/conf.d/site.conf"
NGINX_CF_REALIP="/etc/nginx/conf.d/cloudflare-realip.conf"
FORWARDER_AUTH_SECRET=""

declare -a CF_IPS_V4=()
declare -a CF_IPS_V6=()

# -------------------------
# Helpers
# -------------------------
trim() { echo "${1:-}" | xargs; }
have() { command -v "$1" >/dev/null 2>&1; }
die() { echo "ERROR: $*" >&2; exit 1; }

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

json_array_from_list() {
  local out="[" first=1
  for item in "$@"; do
    if [[ $first -eq 1 ]]; then first=0; else out+=", "; fi
    out+="\"$(json_escape "$item")\""
  done
  out+="]"
  printf '%s' "$out"
}

load_cloudflare_ips() {
  if [[ ${#CF_IPS_V4[@]} -gt 0 || ${#CF_IPS_V6[@]} -gt 0 ]]; then
    return 0
  fi

  local fetched_v4 fetched_v6
  fetched_v4="$(curl -fsSL https://www.cloudflare.com/ips-v4 2>/dev/null || true)"
  fetched_v6="$(curl -fsSL https://www.cloudflare.com/ips-v6 2>/dev/null || true)"

  if [[ -n "$fetched_v4" && -n "$fetched_v6" ]]; then
    mapfile -t CF_IPS_V4 < <(echo "$fetched_v4" | sed '/^\s*$/d')
    mapfile -t CF_IPS_V6 < <(echo "$fetched_v6" | sed '/^\s*$/d')
  else
    CF_IPS_V4=(
      173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
      141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
      197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
      104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
    )
    CF_IPS_V6=(
      2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32
      2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32
    )
  fi
}

detect_os() {
  OS="unknown"
  PKG="unknown"
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    local like="${ID_LIKE:-}"
    local id="${ID:-}"
    if echo "$id $like" | grep -qiE 'debian|ubuntu'; then
      OS="debian"; PKG="apt"
    elif echo "$id $like" | grep -qiE 'rhel|fedora|centos|rocky|almalinux'; then
      OS="rhel"; PKG="dnf"
      if have yum && ! have dnf; then PKG="yum"; fi
    fi
  fi
  echo "    OS: $OS | pkg: $PKG"
}

install_packages() {
  echo "[1/11] Installing packages..."
  if [[ "$PKG" == "apt" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ca-certificates curl nginx openssl ufw jq coreutils
  elif [[ "$PKG" == "dnf" ]]; then
    dnf install -y ca-certificates curl nginx openssl firewalld jq coreutils
  elif [[ "$PKG" == "yum" ]]; then
    yum install -y ca-certificates curl nginx openssl firewalld jq coreutils
  else
    die "Unsupported OS. Install manually: nginx openssl curl jq ufw/firewalld"
  fi
}

enable_services() {
  echo "[2/11] Enabling Nginx..."
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl start nginx  >/dev/null 2>&1 || true

  if [[ "$PKG" == "dnf" || "$PKG" == "yum" ]]; then
    systemctl enable firewalld >/dev/null 2>&1 || true
    systemctl start firewalld  >/dev/null 2>&1 || true
  fi
}

write_static_site() {
  echo "[3/11] Creating static site root..."
  mkdir -p /var/www/site
  chmod 755 /var/www /var/www/site || true

  cat > /var/www/site/index.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Secure Gateway</title>
  <meta name="robots" content="noindex,nofollow" />
  <style>
    body{font-family:system-ui,-apple-system,sans-serif;background:#0c1116;color:#e8eef6;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .container{text-align:center;max-width:520px;padding:40px 20px}
    h1{font-size:2.5rem;margin:0 0 1rem;background:linear-gradient(135deg,#0ea5e9,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
    p{font-size:1.1rem;line-height:1.6;opacity:.85;margin:0 0 1.5rem}
    .badge{display:inline-block;background:rgba(14,165,233,.1);color:#0ea5e9;padding:8px 16px;border-radius:999px;font-size:.9rem;border:1px solid rgba(14,165,233,.3)}
  </style>
</head>
<body>
  <div class="container">
    <h1>Secure Gateway</h1>
    <p>Access through encrypted links only.</p>
    <div class="badge">Protected Service</div>
  </div>
</body>
</html>
HTML

  cat > /var/www/site/404.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Not Found</title>
  <meta name="robots" content="noindex,nofollow" />
  <style>
    body{font-family:system-ui,-apple-system,sans-serif;background:#0c1116;color:#e8eef6;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .container{text-align:center;max-width:520px;padding:40px 20px}
    h1{font-size:4rem;margin:0 0 1rem;color:#6b7280}
    h2{font-size:1.5rem;margin:0 0 1rem}
    p{font-size:1.1rem;line-height:1.6;opacity:.85;margin:0 0 1.5rem}
    a{display:inline-block;background:#0ea5e9;color:white;padding:12px 24px;border-radius:12px;text-decoration:none;font-weight:600}
    a:hover{background:#0284c7}
  </style>
</head>
<body>
  <div class="container">
    <h1>404</h1>
    <h2>Page Not Found</h2>
    <p>The page you're looking for doesn't exist or the link has expired.</p>
    <a href="/">Return to Home</a>
  </div>
</body>
</html>
HTML

  chmod 644 /var/www/site/index.html /var/www/site/404.html
}

# -------------------------
# Domain file + helper commands
# -------------------------
ensure_domains_file() {
  mkdir -p "$(dirname "$DOMAINS_FILE_DEFAULT")"
  touch "$DOMAINS_FILE_DEFAULT"
}

normalize_domain() {
  echo "${1:-}" | tr 'A-Z' 'a-z' | sed 's/^\*\./*./' | sed 's/\.$//' | xargs
}

valid_domain() {
  echo "${1:-}" | grep -qiE '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
}

valid_hostname_entry() {
  local h="${1:-}"
  if [[ "$h" == "*."* ]]; then
    valid_domain "${h#*.}"
  else
    valid_domain "$h"
  fi
}

add_domain() {
  local d
  d="$(normalize_domain "$1")"
  valid_hostname_entry "$d" || die "Invalid domain/hostname entry: $1"

  ensure_domains_file

  if grep -qx "$d" "$DOMAINS_FILE_DEFAULT"; then
    echo "Domain already exists: $d"
    return 0
  fi

  echo "$d" >> "$DOMAINS_FILE_DEFAULT"
  sort -u "$DOMAINS_FILE_DEFAULT" -o "$DOMAINS_FILE_DEFAULT"

  echo "✅ Added domain: $d"
  echo "Next: sudo $0 apply"
}

remove_domain() {
  local d
  d="$(normalize_domain "$1")"

  ensure_domains_file

  if ! grep -qx "$d" "$DOMAINS_FILE_DEFAULT"; then
    echo "Domain not found: $d"
    return 0
  fi

  grep -vx "$d" "$DOMAINS_FILE_DEFAULT" > "${DOMAINS_FILE_DEFAULT}.tmp"
  mv "${DOMAINS_FILE_DEFAULT}.tmp" "$DOMAINS_FILE_DEFAULT"

  echo "🗑️  Removed domain: $d"
  echo "Next: sudo $0 apply"
}

list_domains() {
  local create_file="${1:-1}"
  if [[ "$create_file" == "1" ]]; then
    ensure_domains_file
  fi

  echo "Current domains in ${DOMAINS_FILE_DEFAULT}:"
  if [[ ! -e "$DOMAINS_FILE_DEFAULT" ]]; then
    echo "  (state file not created yet)"
  elif [[ ! -s "$DOMAINS_FILE_DEFAULT" ]]; then
    echo "  (empty)"
  else
    nl -ba "$DOMAINS_FILE_DEFAULT"
  fi
}
load_domains() {
  echo "[*] Loading domains..."

  mkdir -p "$STATE_DIR"

  # Seed from a local domains.txt or the built-in fallback only on first run.
  # An existing empty state file is intentional state and should fail loudly below.
  if [[ ! -e "$DOMAINS_FILE_DEFAULT" ]]; then
    mkdir -p "$(dirname "$DOMAINS_FILE_DEFAULT")"
    if [[ -s "./domains.txt" ]]; then
      cp -f "./domains.txt" "$DOMAINS_FILE_DEFAULT"
    else
      printf "%s\n" "${DOMAINS_FALLBACK[@]}" > "$DOMAINS_FILE_DEFAULT"
    fi
  fi

  mapfile -t DOMAINS < <(grep -vE '^\s*#' "$DOMAINS_FILE_DEFAULT" | sed '/^\s*$/d' | awk '{print $1}')

  if [[ "${#DOMAINS[@]}" -eq 0 ]]; then
    die "No domains found in $DOMAINS_FILE_DEFAULT"
  fi

  # Normalize + validate (basic)
  NORMALIZED=()
  for d in "${DOMAINS[@]}"; do
    d="$(trim "$d")"
    d="${d%.}"
    [[ -z "$d" ]] && continue
    if ! valid_hostname_entry "$d"; then
      die "Invalid domain/hostname entry in domains file: $d"
    fi
    NORMALIZED+=("$(echo "$d" | tr 'A-Z' 'a-z')")
  done
  DOMAINS=("${NORMALIZED[@]}")

  PRIMARY_DOMAIN="${DOMAINS[0]}"
  echo "    Domains: ${DOMAINS[*]}"
}

# -------------------------
# Build hostnames for wildcard + cert + nginx
# -------------------------
build_hostnames() {
  ALL_HOSTNAMES=()
  for d in "${DOMAINS[@]}"; do
    if [[ "$d" == "*."* ]]; then
      # Explicit wildcard entry (e.g. *.r.af.d.example.com): keep as-is,
      # do not expand with another wildcard/www.
      ALL_HOSTNAMES+=("$d")
      continue
    fi

    ALL_HOSTNAMES+=("$d")

    if [[ "$ENABLE_WILDCARDS" == "1" ]]; then
      ALL_HOSTNAMES+=("*.$d")
    fi

    if [[ "$INCLUDE_WWW" == "1" ]]; then
      ALL_HOSTNAMES+=("www.$d")
    fi
  done

  # De-duplicate while preserving order
  DEDUP=()
  for h in "${ALL_HOSTNAMES[@]}"; do
    local seen=0
    for x in "${DEDUP[@]}"; do
      [[ "$x" == "$h" ]] && seen=1 && break
    done
    [[ $seen -eq 0 ]] && DEDUP+=("$h")
  done
  ALL_HOSTNAMES=("${DEDUP[@]}")

  [[ "${#ALL_HOSTNAMES[@]}" -gt 0 ]] || die "No hostnames built."

  SAN_LIST=""
  for h in "${ALL_HOSTNAMES[@]}"; do
    SAN_LIST+="${SAN_LIST:+,}DNS:${h}"
  done

  HOSTNAMES_JSON="$(json_array_from_list "${ALL_HOSTNAMES[@]}")"
  SERVER_NAMES="$(printf '%s ' "${ALL_HOSTNAMES[@]}")"

  echo "    Hostnames for cert/nginx: ${ALL_HOSTNAMES[*]}"
}

preflight_checks() {
  echo "[*] Preflight checks..."

  [[ -z "${BACKEND_URL:-}" ]] && die "BACKEND_URL is empty"
  [[ -z "${CF_API_TOKEN:-}" ]] && die "CF_API_TOKEN is empty"

  if [[ "$CF_API_TOKEN" == "PUT_YOUR_NEW_TOKEN_HERE" ]]; then
    die "Replace CF_API_TOKEN or export CF_API_TOKEN in your shell."
  fi

  if ! echo "$BACKEND_URL" | grep -qiE '^https://'; then
    die "BACKEND_URL must start with https://"
  fi

  BACKEND_HOST="$(echo "$BACKEND_URL" | sed -E 's#^https://([^/]+).*#\1#')"
}

# -------------------------
# Nginx + Cloudflare Real IP
# -------------------------
write_cloudflare_realip_conf() {
  echo "[4/11] Writing Cloudflare real-IP config..."
  load_cloudflare_ips
  cat > "$NGINX_CF_REALIP" <<'NGINX'
real_ip_header CF-Connecting-IP;
real_ip_recursive on;

# Only preserve Cloudflare proof/visitor headers after ngx_http_realip_module
# has verified the immediate peer as a configured Cloudflare edge. When realip
# accepts a Cloudflare peer, $remote_addr is rewritten to CF-Connecting-IP and
# $realip_remote_addr retains the original edge IP. For direct origin hits,
# those values remain identical, so the mapped header values are empty and
# proxy_set_header strips any spoofed client-supplied Cloudflare headers.
map "$realip_remote_addr|$remote_addr" $mds_cf_peer_verified {
  default 1;
  "|" 0;
  ~^\| 0;
  ~^([^|]+)\|\1$ 0;
}
map $mds_cf_peer_verified $mds_cf_connecting_ip {
  1 $remote_addr;
  default "";
}
map $mds_cf_peer_verified $mds_cf_ray {
  1 $http_cf_ray;
  default "";
}
map $mds_cf_peer_verified $mds_cf_visitor {
  1 $http_cf_visitor;
  default "";
}
map $mds_cf_peer_verified $mds_cf_ipcountry {
  1 $http_cf_ipcountry;
  default "";
}
NGINX
  for cidr in "${CF_IPS_V4[@]}"; do
    echo "set_real_ip_from ${cidr};" >> "$NGINX_CF_REALIP"
  done
  for cidr in "${CF_IPS_V6[@]}"; do
    echo "set_real_ip_from ${cidr};" >> "$NGINX_CF_REALIP"
  done
}

disable_conflicts() {
  echo "[5/11] Disabling common conflicting default configs..."
  for f in /etc/nginx/conf.d/parking.conf /etc/nginx/conf.d/reuseport.conf /etc/nginx/conf.d/default.conf; do
    [[ -f "$f" ]] && mv -f "$f" "${f}.disabled.$(date +%s)"
  done
  if [[ -d /etc/nginx/sites-enabled && -e /etc/nginx/sites-enabled/default ]]; then
    mv -f /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.disabled.$(date +%s) || true
  fi
}

resolve_web_port_conflicts() {
  echo "[*] Checking for web server port conflicts..."

  local apache_changed=0

  # Common VPS images ship with Apache already enabled. This installer owns
  # ports 80/443 through Nginx, so Apache/httpd can be safely stopped before
  # Nginx starts. Other processes are not killed automatically.
  if have systemctl; then
    if systemctl is-active --quiet apache2 2>/dev/null; then
      echo "    Apache detected (apache2). Stopping and disabling it..."
      systemctl stop apache2 >/dev/null 2>&1 || true
      systemctl disable apache2 >/dev/null 2>&1 || true
      apache_changed=1
    fi

    if systemctl is-active --quiet httpd 2>/dev/null; then
      echo "    Apache detected (httpd). Stopping and disabling it..."
      systemctl stop httpd >/dev/null 2>&1 || true
      systemctl disable httpd >/dev/null 2>&1 || true
      apache_changed=1
    fi
  fi

  if [[ "$apache_changed" == "1" ]]; then
    echo "    ✅ Apache stopped/disabled. Continuing with Nginx install."
  fi

  if have ss && ss -lntp 2>/dev/null | grep -qE ':(80|443)\s'; then
    local listeners
    listeners="$(ss -lntp 2>/dev/null | grep -E ':(80|443)\s' || true)"

    # If the only listener is nginx, this is fine for re-runs/apply.
    if echo "$listeners" | grep -q 'users:(("nginx"' && ! echo "$listeners" | grep -vq 'users:(("nginx"'; then
      echo "    Existing Nginx listener detected. Reusing it."
      return 0
    fi

    # Try one more Apache cleanup by package/service name if the active check
    # missed stale workers or service state.
    if echo "$listeners" | grep -qE 'users:\(\("(apache2|httpd)"'; then
      echo "    Apache is still holding port 80/443. Retrying stop..."
      systemctl stop apache2 >/dev/null 2>&1 || true
      systemctl disable apache2 >/dev/null 2>&1 || true
      systemctl stop httpd >/dev/null 2>&1 || true
      systemctl disable httpd >/dev/null 2>&1 || true
      sleep 1
      listeners="$(ss -lntp 2>/dev/null | grep -E ':(80|443)\s' || true)"
    fi

    if [[ -n "$listeners" ]]; then
      echo
      echo "ERROR: Port 80 or 443 is still in use by another process:"
      echo "$listeners"
      echo
      echo "Stop the listed service/process, then rerun: sudo $0 apply"
      die "Cannot continue while 80/443 are occupied by a non-Nginx process."
    fi
  fi

  echo "    ✅ Ports 80/443 are available for Nginx."
}

nginx_supports_http2_on() {
  local ver major minor
  ver="$(nginx -v 2>&1 | sed -E 's/.*nginx\/([0-9]+)\.([0-9]+).*/\1.\2/')"
  major="$(echo "$ver" | cut -d. -f1)"
  minor="$(echo "$ver" | cut -d. -f2)"
  [[ "$major" -gt 1 ]] && return 0
  [[ "$minor" -ge 25 ]] && return 0
  return 1
}

ensure_forwarder_auth_secret() {
  mkdir -p "$STATE_DIR"

  if [[ -n "${MDS_FORWARDER_AUTH_SECRET:-}" ]]; then
    FORWARDER_AUTH_SECRET="$MDS_FORWARDER_AUTH_SECRET"
  elif [[ -s "$FORWARDER_SECRET_PATH" ]]; then
    FORWARDER_AUTH_SECRET="$(tr -d '[:space:]' < "$FORWARDER_SECRET_PATH")"
  else
    FORWARDER_AUTH_SECRET="$(openssl rand -hex 32)"
    printf "%s\n" "$FORWARDER_AUTH_SECRET" > "$FORWARDER_SECRET_PATH"
    chmod 600 "$FORWARDER_SECRET_PATH"
  fi

  [[ -n "$FORWARDER_AUTH_SECRET" ]] || die "Could not create forwarder auth secret"
  if ! [[ "$FORWARDER_AUTH_SECRET" =~ ^[A-Za-z0-9._~:-]{16,256}$ ]]; then
    die "Forwarder auth secret contains unsupported characters; use a 16-256 char token from [A-Za-z0-9._~:-]"
  fi

  if [[ ! -s "$FORWARDER_SECRET_PATH" ]] || [[ "$(tr -d '[:space:]' < "$FORWARDER_SECRET_PATH" 2>/dev/null || true)" != "$FORWARDER_AUTH_SECRET" ]]; then
    printf "%s\n" "$FORWARDER_AUTH_SECRET" > "$FORWARDER_SECRET_PATH"
    chmod 600 "$FORWARDER_SECRET_PATH"
  fi
}

write_site_conf() {
  echo "[6/11] Writing Nginx site config (wildcards + multi-domain)..."

  local http2_suffix=""
  if nginx_supports_http2_on; then
    http2_suffix="http2"
  fi

  cat > "$NGINX_SITE_CONF" <<NGINX
server {
  listen 80;
  listen [::]:80;
  server_name ${SERVER_NAMES};
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl ${http2_suffix};
  listen [::]:443 ssl ${http2_suffix};

  server_name ${SERVER_NAMES};

  ssl_certificate     ${CERT_PATH};
  ssl_certificate_key ${KEY_PATH};

  merge_slashes off;

  resolver 1.1.1.1 8.8.8.8 ipv6=off valid=300s;
  resolver_timeout 5s;

  set \$upstream ${BACKEND_URL};

  root /var/www/site;
  index index.html;

  server_tokens off;

  add_header X-Content-Type-Options nosniff;
  add_header X-Frame-Options DENY;
  add_header Referrer-Policy strict-origin-when-cross-origin;

  error_page 404 /404.html;

  # Keep only explicit access to local 404 page.
  # All primary routes (including /) should be served by the upstream app.
  location = /404.html { try_files /404.html =404; }

  location ~* \\.(css|js|png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf|map)$ {
    try_files \$uri =404;
    access_log off;
    expires 1h;
  }

  location / {
    proxy_pass \$upstream;

    proxy_ssl_server_name on;
    proxy_ssl_name ${BACKEND_HOST};

    proxy_set_header Host ${BACKEND_HOST};
    proxy_set_header X-Forwarded-Host \$host;

    proxy_set_header X-Forwarded-Proto \$scheme;

    # Preserve Cloudflare visitor identity for the upstream app only after
    # cloudflare-realip.conf proves the direct peer is a known Cloudflare edge.
    # Verified Cloudflare requests rewrite \$remote_addr to CF-Connecting-IP while
    # retaining the edge in \$realip_remote_addr; direct-to-VPS hits leave those
    # values equal, so spoofed Cloudflare proof headers are stripped.
    proxy_set_header CF-Connecting-IP \$mds_cf_connecting_ip;
    proxy_set_header CF-Ray \$mds_cf_ray;
    proxy_set_header CF-Visitor \$mds_cf_visitor;
    proxy_set_header CF-IPCountry \$mds_cf_ipcountry;
    proxy_set_header X-MDS-Forwarder-Auth ${FORWARDER_AUTH_SECRET};
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For "\$remote_addr, \$realip_remote_addr";

    proxy_http_version 1.1;
    proxy_set_header Connection "";

    proxy_redirect off;
  }
}
NGINX
}

# -------------------------
# Cert logic (idempotent + rotation trigger)
# -------------------------
cert_days_left() {
  [[ -f "$CERT_PATH" ]] || return 1
  local enddate epoch_end epoch_now
  enddate="$(openssl x509 -enddate -noout -in "$CERT_PATH" 2>/dev/null | sed 's/^notAfter=//')" || return 1
  epoch_end="$(date -d "$enddate" +%s 2>/dev/null)" || return 1
  epoch_now="$(date +%s)"
  echo $(( (epoch_end - epoch_now) / 86400 ))
}

should_reissue_cert() {
  [[ -f "$CERT_PATH" && -f "$KEY_PATH" ]] || return 0

  local newhash oldhash days
  newhash="$(printf '%s\n' "${ALL_HOSTNAMES[@]}" | sha256sum | awk '{print $1}')"
  oldhash="$(cat "$HOSTNAMES_HASH_PATH" 2>/dev/null || true)"
  if [[ "$newhash" != "$oldhash" ]]; then
    echo "    Domains/hostnames changed -> will re-issue Origin CA cert."
    return 0
  fi

  days="$(cert_days_left || echo 0)"
  if [[ "$days" -lt "$CERT_RENEW_IF_DAYS_LEFT_LT" ]]; then
    echo "    Cert expires in ${days} days (<${CERT_RENEW_IF_DAYS_LEFT_LT}) -> will re-issue."
    return 0
  fi

  return 1
}

create_origin_cert_via_api_if_needed() {
  echo "[7/11] Cloudflare Origin CA certificate (wildcards enabled)..."
  mkdir -p "$CF_SSL_DIR"
  chmod 700 "$CF_SSL_DIR"

  if [[ ! -f "$KEY_PATH" ]]; then
    openssl genrsa -out "$KEY_PATH" 2048
    chmod 600 "$KEY_PATH"
  fi

  if ! should_reissue_cert; then
    echo "    Cert already matches current hostnames and is not expiring soon. Skipping re-issue."
    return 0
  fi

  if [[ -f "$CERT_PATH" ]]; then
    cp -f "$CERT_PATH" "${CERT_PATH}.bak.$(date +%s)" || true
  fi

  openssl req -new -key "$KEY_PATH" \
    -subj "/CN=${PRIMARY_DOMAIN}" \
    -addext "subjectAltName=${SAN_LIST}" \
    -out "$CSR_PATH"

  CSR_JSON_ESCAPED="$(awk '{printf "%s\\n", $0}' "$CSR_PATH")"

  RESP="$(
    curl -sS -X POST "https://api.cloudflare.com/client/v4/certificates" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "{
        \"csr\": \"${CSR_JSON_ESCAPED}\",
        \"hostnames\": ${HOSTNAMES_JSON},
        \"requested_validity\": 5475,
        \"request_type\": \"origin-rsa\"
      }"
  )"

  if ! echo "$RESP" | jq -e '.success == true' >/dev/null 2>&1; then
    echo "$RESP" | jq -r '.errors[]?.message' 2>/dev/null || true
    die "Cloudflare API cert creation failed."
  fi

  echo "$RESP" | jq -r '.result.certificate' > "$CERT_PATH"
  chmod 644 "$CERT_PATH"

  CERT_MD5="$(openssl x509 -noout -modulus -in "$CERT_PATH" | openssl md5 | awk '{print $2}')"
  KEY_MD5="$(openssl rsa  -noout -modulus -in "$KEY_PATH"  | openssl md5 | awk '{print $2}')"
  [[ "$CERT_MD5" == "$KEY_MD5" ]] || die "Origin cert and key mismatch after API generation."

  printf '%s\n' "${ALL_HOSTNAMES[@]}" | sha256sum | awk '{print $1}' > "$HOSTNAMES_HASH_PATH"

  echo "    ✅ Origin CA cert issued for: ${ALL_HOSTNAMES[*]}"
}

# -------------------------
# Firewall
# -------------------------
configure_firewall_cloudflare_only() {
  echo "[8/11] Firewall: lock 80/443 to Cloudflare only..."
  load_cloudflare_ips

  if [[ "$PKG" == "apt" ]]; then
    ufw allow OpenSSH >/dev/null 2>&1 || true

    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true

    for cidr in "${CF_IPS_V4[@]}"; do
      ufw allow from "$cidr" to any port 80 proto tcp >/dev/null
      ufw allow from "$cidr" to any port 443 proto tcp >/dev/null
    done

    for cidr in "${CF_IPS_V6[@]}"; do
      ufw allow from "$cidr" to any port 80 proto tcp >/dev/null || true
      ufw allow from "$cidr" to any port 443 proto tcp >/dev/null || true
    done

    ufw --force enable >/dev/null 2>&1 || true
  else
    firewall-cmd --permanent --remove-service=http >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-service=https >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true

    firewall-cmd --permanent --new-ipset=cloudflare4 --type=hash:net >/dev/null 2>&1 || true
    firewall-cmd --permanent --new-ipset=cloudflare6 --type=hash:net >/dev/null 2>&1 || true

    for cidr in "${CF_IPS_V4[@]}"; do
      firewall-cmd --permanent --ipset=cloudflare4 --add-entry="$cidr" >/dev/null 2>&1 || true
    done
    for cidr in "${CF_IPS_V6[@]}"; do
      firewall-cmd --permanent --ipset=cloudflare6 --add-entry="$cidr" >/dev/null 2>&1 || true
    done

    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source ipset="cloudflare4" port port="80" protocol="tcp" accept' >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source ipset="cloudflare4" port port="443" protocol="tcp" accept' >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-rich-rule='rule family="ipv6" source ipset="cloudflare6" port port="80" protocol="tcp" accept' >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-rich-rule='rule family="ipv6" source ipset="cloudflare6" port port="443" protocol="tcp" accept' >/dev/null 2>&1 || true

    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

test_and_reload_nginx() {
  echo "[9/11] Testing + reloading Nginx..."
  nginx -t
  systemctl reload nginx
}

print_banner() {
  cat <<'BANNER'
============================================================
 Cloudflare Domains Route Installer
============================================================
This tool routes Cloudflare-orange-cloud domains through this VPS,
locks web ports to Cloudflare, preserves real visitor IP headers,
and proxies traffic to your Railway backend.
BANNER
}

read_prompt() {
  local prompt="$1"
  local default="${2:-}"
  local value

  if [[ -n "$default" ]]; then
    prompt="${prompt} [${default}]: "
  else
    prompt="${prompt}: "
  fi

  if [[ -t 0 ]]; then
    read -r -e -p "$prompt" value
  else
    read -r -p "$prompt" value
  fi

  if [[ -z "$value" && -n "$default" ]]; then
    value="$default"
  fi
  printf '%s\n' "$value"
}

pause_menu() {
  if [[ -t 0 ]]; then
    echo
    read -r -e -p "Press Enter to return to the menu..." _unused
  fi
}

for_each_domain_input() {
  local raw="$1"
  local action="$2"
  local item

  raw="${raw//,/ }"
  for item in $raw; do
    [[ -z "$item" ]] && continue
    "$action" "$item"
  done
}

interactive_add_domains() {
  echo "Enter one or more domains. Separate multiple domains with spaces or commas."
  local raw
  raw="$(read_prompt "Domain(s) to add")"
  [[ -z "$raw" ]] && { echo "No domains entered."; return 0; }
  for_each_domain_input "$raw" add_domain
  echo "Next: choose option 8 to apply/reinstall the Nginx configuration."
}

interactive_remove_domains() {
  echo "Enter one or more domains to remove. Separate multiple domains with spaces or commas."
  local raw
  raw="$(read_prompt "Domain(s) to remove")"
  [[ -z "$raw" ]] && { echo "No domains entered."; return 0; }
  for_each_domain_input "$raw" remove_domain
  echo "Next: choose option 8 to apply/reinstall the Nginx configuration."
}

show_menu() {
  while true; do
    print_banner
    cat <<'MENU'

Options:
  1. Install                 - Install packages, Nginx config, Cloudflare Origin cert, firewall rules
  2. Uninstall               - Remove generated configs/state and disable generated routing
  3. Status                  - Show service/config/firewall/domain status
  4. Diagnose                - Check common causes of failed install and repair safe items
  5. Add Domain(s)           - Add one or more domains to the installer state
  6. Remove Domain(s)        - Remove one or more domains from the installer state
  7. List Domain(s)          - Show currently configured domains
  8. Apply Changes/Reinstall - Rebuild config/certs/firewall after domain or backend changes
  9. Exit                    - Leave without making more changes

MENU
    local choice
    choice="$(read_prompt "Choose an option" "1")"
    case "$choice" in
      1) main; pause_menu ;;
      2) uninstall; pause_menu ;;
      3) status; pause_menu ;;
      4) diagnose; pause_menu ;;
      5) interactive_add_domains; pause_menu ;;
      6) interactive_remove_domains; pause_menu ;;
      7) list_domains 0; pause_menu ;;
      8) main; pause_menu ;;
      9|q|Q|exit|quit) echo "Goodbye."; return 0 ;;
      *) echo "Invalid option: ${choice:-empty}"; pause_menu ;;
    esac
  done
}
remove_file_or_dir() {
  local target="$1"
  if [[ -e "$target" || -L "$target" ]]; then
    rm -rf "$target"
    echo "  removed $target"
  fi
}

uninstall() {
  echo "[uninstall] Removing generated Cloudflare route files..."
  detect_os

  remove_file_or_dir "$NGINX_SITE_CONF"
  remove_file_or_dir "$NGINX_CF_REALIP"
  remove_file_or_dir "$CF_SSL_DIR"
  remove_file_or_dir "$STATE_DIR"
  remove_file_or_dir /var/www/site

  if have nginx; then
    nginx -t && systemctl reload nginx || true
  fi

  echo "[uninstall] Firewall/package cleanup is intentionally conservative."
  echo "            Review UFW/firewalld rules manually if this VPS is no longer Cloudflare-only."
  echo "✅ Uninstall cleanup complete."
}

status() {
  echo "[status] Cloudflare route status"
  detect_os
  echo
  echo "Files:"
  for f in "$NGINX_SITE_CONF" "$NGINX_CF_REALIP" "$CERT_PATH" "$KEY_PATH" "$DOMAINS_FILE_DEFAULT" "$FORWARDER_SECRET_PATH"; do
    if [[ -e "$f" ]]; then echo "  ✅ $f"; else echo "  ❌ $f"; fi
  done

  echo
  echo "Services:"
  if have systemctl; then
    systemctl is-active --quiet nginx >/dev/null 2>&1 && echo "  ✅ nginx active" || echo "  ❌ nginx not active"
  else
    echo "  ⚠️ systemctl unavailable"
  fi

  echo
  echo "Nginx config test:"
  if have nginx; then nginx -t || true; else echo "  ❌ nginx not installed"; fi

  echo
  echo "Listening ports:"
  ss -lntp 2>/dev/null | egrep ':80|:443' || echo "  ⚠️ nothing listening on 80/443 or ss unavailable"

  echo
  echo "Domains:"
  list_domains 0 || true
}

diagnose() {
  echo "[diagnose] Checking common install problems..."
  detect_os

  if [[ "$OS" == "unknown" ]]; then
    echo "  ❌ Unsupported/unknown OS. Install nginx/curl/openssl/jq/firewall manually."
  fi

  for cmd in curl nginx openssl jq ss; do
    if have "$cmd"; then echo "  ✅ command: $cmd"; else echo "  ❌ missing command: $cmd"; fi
  done

  if [[ "$CF_API_TOKEN" == "PUT_YOUR_NEW_TOKEN_HERE" ]]; then
    echo "  ❌ CF_API_TOKEN is not set. Export CF_API_TOKEN before install."
  else
    echo "  ✅ CF_API_TOKEN is set"
  fi

  if echo "$BACKEND_URL" | grep -qiE '^https://'; then
    echo "  ✅ BACKEND_URL uses https: $BACKEND_URL"
  else
    echo "  ❌ BACKEND_URL must start with https://"
  fi

  if [[ -s "$DOMAINS_FILE_DEFAULT" ]]; then
    echo "  ✅ domains file has entries: $DOMAINS_FILE_DEFAULT"
  else
    echo "  ⚠️ domains file is empty: $DOMAINS_FILE_DEFAULT"
  fi

  if [[ -s "$FORWARDER_SECRET_PATH" || -n "${MDS_FORWARDER_AUTH_SECRET:-}" ]]; then
    echo "  ✅ forwarder auth secret is available"
  else
    echo "  ⚠️ forwarder auth secret not generated yet; run option 1 or 8"
  fi

  echo
  echo "[diagnose] Nginx syntax:"
  if have nginx; then nginx -t || true; fi

  echo
  echo "[diagnose] Safe repair actions:"
  if have nginx; then
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl start nginx >/dev/null 2>&1 || true
    echo "  ✅ ensured nginx service is enabled/started when systemd is available"
  fi

  echo
  echo "If visitor IP still logs as the VPS IP, confirm you reran option 1 or 8"
  echo "and copied MDS_FORWARDER_AUTH_SECRET to Railway. TRUST_CLOUDFLARE_XFF_CHAIN"
  echo "is no longer required for the authenticated VPS forwarder path."
}

final_checks() {
  echo "[10/11] Final checks..."
  echo "Nginx listening:"
  ss -lntp | egrep ':80|:443' || true

  echo
  echo "Try these:"
  for d in "${DOMAINS[@]}"; do
    echo "  curl -I https://${d}/"
    echo "  curl -I https://sub.${d}/  (will work if you set wildcard DNS record '*')"
  done

  echo
  echo "Cloudflare reminders:"
  echo "  - For EACH domain: DNS A record for @ -> VPS IP must be Proxied (orange cloud)"
  echo "  - For wildcard subdomains: add DNS record '*' -> VPS IP (Proxied) (optional)"
  echo "  - Deep subdomain wildcards require explicit deeper wildcard entries (e.g. '*.r.af.d.example.com')."
  echo "  - SSL/TLS mode: Full (strict)"
  echo
  echo "Railway env to keep:"
  echo "  TRUST_PROXY_HOPS=1"
  echo "  MDS_FORWARDER_AUTH_SECRET=${FORWARDER_AUTH_SECRET}"
  echo
  echo "Railway env to remove unless you intentionally use a private/trusted XFF chain:"
  echo "  TRUST_CLOUDFLARE_XFF_CHAIN"
  echo
  echo "Important: keep MDS_FORWARDER_AUTH_SECRET private. It lets Railway verify"
  echo "that Cloudflare visitor IP headers came from this VPS, not a direct spoof."
}

main() {
  echo "[*] Detecting OS..."
  detect_os

  install_packages
  resolve_web_port_conflicts
  enable_services
  write_static_site

  load_domains
  preflight_checks
  build_hostnames

  write_cloudflare_realip_conf
  disable_conflicts
  ensure_forwarder_auth_secret
  write_site_conf
  create_origin_cert_via_api_if_needed
  configure_firewall_cloudflare_only
  test_and_reload_nginx
  final_checks

  echo
  echo "✅ DONE."
  echo "Domains file: ${DOMAINS_FILE_DEFAULT}"
}

# -------------------------
# CLI Router
# -------------------------
case "${1:-}" in
  add-domain)
    [[ -z "${2:-}" ]] && die "Usage: $0 add-domain example.com"
    add_domain "$2"
    exit 0
    ;;
  remove-domain)
    [[ -z "${2:-}" ]] && die "Usage: $0 remove-domain example.com"
    remove_domain "$2"
    exit 0
    ;;
  list-domains)
    list_domains 0
    exit 0
    ;;
  install|apply|reinstall)
    main
    exit 0
    ;;
  uninstall)
    uninstall
    exit 0
    ;;
  status)
    status
    exit 0
    ;;
  diagnose)
    diagnose
    exit 0
    ;;
  "")
    if [[ -t 0 ]]; then
      show_menu
    else
      main
    fi
    exit 0
    ;;
  *)
    die "Unknown command: ${1:-}
Usage:
  $0                 # interactive menu
  $0 install|apply|reinstall
  $0 uninstall
  $0 status
  $0 diagnose
  $0 add-domain example.com
  $0 remove-domain example.com
  $0 list-domains"
    ;;
esac
