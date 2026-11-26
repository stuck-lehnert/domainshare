#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[init] %s\n' "$*"
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf '[init] ERROR: missing required env var %s\n' "$name" >&2
    exit 1
  fi
}

append_winbind_to_nss() {
  sed -ri '/^passwd:/ { /winbind/! s/$/ winbind/ }' /etc/nsswitch.conf
  sed -ri '/^group:/ { /winbind/! s/$/ winbind/ }' /etc/nsswitch.conf
}

detect_modules_dir() {
  smbd -b | sed -n 's/^ *MODULESDIR: //p' | head -n1
}

require_vfs_modules() {
  local modules_dir=""
  modules_dir="$(detect_modules_dir)"
  if [[ -z "$modules_dir" ]]; then
    printf '[init] ERROR: unable to detect Samba MODULESDIR via smbd -b\n' >&2
    exit 1
  fi

  local missing=0
  local module
  for module in acl_xattr xattr_tdb recycle full_audit; do
    if [[ ! -f "$modules_dir/vfs/${module}.so" ]]; then
      printf '[init] ERROR: missing VFS module %s at %s/vfs/%s.so\n' "$module" "$modules_dir" "$module" >&2
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    printf '[init] Install package samba-vfs-modules and rebuild the image.\n' >&2
    exit 1
  fi
}

derive_netbios_name() {
  local raw_name="${NETBIOS_NAME:-DOMAINSHARE}"
  local upper_name="${raw_name^^}"
  local cleaned_name
  cleaned_name="$(printf '%s' "$upper_name" | tr -cd 'A-Z0-9')"

  if [[ -z "$cleaned_name" ]]; then
    cleaned_name="DOMAINSHARE"
  fi

  if [[ ${#cleaned_name} -gt 15 ]]; then
    log "NETBIOS_NAME derived from '${raw_name}' exceeds 15 chars, truncating."
  fi

  export NETBIOS_NAME="${cleaned_name:0:15}"
}

derive_backup_start_hour() {
  local raw_hour="${BACKUP_START_HOUR:-2}"
  if [[ "$raw_hour" =~ ^[0-9]+$ ]] && (( raw_hour >= 0 && raw_hour <= 23 )); then
    printf '%d\n' "$raw_hour"
    return
  fi

  log "Invalid BACKUP_START_HOUR '${raw_hour}', defaulting to 2."
  printf '2\n'
}

derive_ad_dns_name() {
  local raw_name="${AD_DNS_NAME:-}"
  local host_name="${SAMBA_HOSTNAME:-}"

  if [[ -z "$host_name" ]]; then
    host_name="$(hostname -s 2>/dev/null || true)"
  fi
  if [[ -z "$host_name" ]]; then
    host_name="${NETBIOS_NAME,,}"
  fi

  if [[ -n "$raw_name" ]]; then
    if [[ "$raw_name" == *.* ]]; then
      AD_DNS_NAME="$raw_name"
    else
      AD_DNS_NAME="${raw_name}.${DOMAIN}"
    fi
  else
    AD_DNS_NAME="${host_name}.${DOMAIN}"
  fi

  export AD_DNS_NAME="${AD_DNS_NAME,,}"
}

resolve_sid_to_group() {
  local sid="$1"
  local resolved_name=""
  local sid_output=""

  if sid_output="$(wbinfo --sid-to-fullname "$sid" 2>/dev/null)"; then
    resolved_name="${sid_output%%$'\t'*}"
    resolved_name="$(printf '%s' "$resolved_name" | sed -E 's/[[:space:]]+[0-9]+$//')"
  fi

  if [[ -z "$resolved_name" ]] && sid_output="$(wbinfo -s "$sid" 2>/dev/null)"; then
    resolved_name="$(printf '%s' "$sid_output" | sed -E 's/[[:space:]]+[0-9]+$//')"
  fi

  if [[ -z "$resolved_name" ]]; then
    printf '[init] ERROR: unable to resolve SID %s via winbind\n' "$sid" >&2
    return 1
  fi

  if [[ "$resolved_name" != *\\* ]]; then
    resolved_name="${WORKGROUP}\\${resolved_name}"
  fi
  printf '%s\n' "$resolved_name"
}

ensure_machine_keytab() {
  local keytab_path="/var/lib/samba/private/krb5.keytab"
  mkdir -p /var/lib/samba/private

  if [[ ! -s /etc/krb5.keytab ]]; then
    if ! net ads keytab create -P >/dev/null 2>&1; then
      if [[ -n "${JOIN_USER:-}" && -n "${JOIN_PASSWORD:-}" ]]; then
        printf '%s\n' "$JOIN_PASSWORD" | net ads keytab create -U "$JOIN_USER" >/dev/null 2>&1 || true
      fi
    fi
  fi

  if [[ -s /etc/krb5.keytab ]]; then
    cp /etc/krb5.keytab "$keytab_path"
    chmod 600 "$keytab_path"
  fi
}

resolve_share_groups_from_sids() {
  export DOMAIN_USERS_GROUP
  DOMAIN_USERS_GROUP="$(resolve_sid_to_group "$DOMAIN_USERS_SID")"

  export DOMAIN_ADMINS_GROUP
  DOMAIN_ADMINS_GROUP="$(resolve_sid_to_group "$DOMAIN_ADMINS_SID")"

  export FSLOGIX_GROUP
  FSLOGIX_GROUP="$(resolve_sid_to_group "$FSLOGIX_GROUP_SID")"

  log "Resolved DOMAIN_USERS_SID to '${DOMAIN_USERS_GROUP}'"
  log "Resolved DOMAIN_ADMINS_SID to '${DOMAIN_ADMINS_GROUP}'"
  log "Resolved FSLOGIX_GROUP_SID to '${FSLOGIX_GROUP}'"
}

render_krb5_conf() {
  cat > /etc/krb5.conf <<EOF
[libdefaults]
 default_realm = ${REALM}
 dns_lookup_realm = false
 dns_lookup_kdc = true
 rdns = false
 ticket_lifetime = 24h
 forwardable = true

[realms]
 ${REALM} = {
  kdc = ${DOMAIN}
  admin_server = ${DOMAIN}
 }

[domain_realm]
 .${DOMAIN} = ${REALM}
 ${DOMAIN} = ${REALM}
EOF
}

render_smb_conf() {
  envsubst < /app/smb.conf.template > /etc/samba/smb.conf
  testparm -s /etc/samba/smb.conf >/dev/null
}

write_runtime_env_file() {
  {
    printf 'export REALM=%q\n' "$REALM"
    printf 'export WORKGROUP=%q\n' "$WORKGROUP"
    printf 'export DOMAIN=%q\n' "$DOMAIN"
    printf 'export NETBIOS_NAME=%q\n' "$NETBIOS_NAME"
    printf 'export AD_DNS_NAME=%q\n' "$AD_DNS_NAME"
    if [[ -n "${AD_DNS_IP:-}" ]]; then
      printf 'export AD_DNS_IP=%q\n' "$AD_DNS_IP"
    fi
    printf 'export DOMAIN_USERS_SID=%q\n' "$DOMAIN_USERS_SID"
    printf 'export DOMAIN_ADMINS_SID=%q\n' "$DOMAIN_ADMINS_SID"
    printf 'export FSLOGIX_GROUP_SID=%q\n' "$FSLOGIX_GROUP_SID"
    printf 'export DOMAIN_USERS_GROUP=%q\n' "$DOMAIN_USERS_GROUP"
    printf 'export DOMAIN_ADMINS_GROUP=%q\n' "$DOMAIN_ADMINS_GROUP"
    printf 'export FSLOGIX_GROUP=%q\n' "$FSLOGIX_GROUP"
    printf 'export BACKUP_START_HOUR=%q\n' "$BACKUP_START_HOUR"
    if [[ -n "${BACKUP_DESTINATION:-}" ]]; then
      printf 'export BACKUP_DESTINATION=%q\n' "$BACKUP_DESTINATION"
    fi
    if [[ -n "${BACKUP_RETENTION_DAILY:-}" ]]; then
      printf 'export BACKUP_RETENTION_DAILY=%q\n' "$BACKUP_RETENTION_DAILY"
    fi
    if [[ -n "${BACKUP_RETENTION_WEEKLY:-}" ]]; then
      printf 'export BACKUP_RETENTION_WEEKLY=%q\n' "$BACKUP_RETENTION_WEEKLY"
    fi
    if [[ -n "${BACKUP_RETENTION_MONTHLY:-}" ]]; then
      printf 'export BACKUP_RETENTION_MONTHLY=%q\n' "$BACKUP_RETENTION_MONTHLY"
    fi
    if [[ -n "${BACKUP_RETENTION_YEARLY:-}" ]]; then
      printf 'export BACKUP_RETENTION_YEARLY=%q\n' "$BACKUP_RETENTION_YEARLY"
    fi
    if [[ -n "${BACKUP_LOG_FILE:-}" ]]; then
      printf 'export BACKUP_LOG_FILE=%q\n' "$BACKUP_LOG_FILE"
    fi
    printf 'export BACKUP_AUTO_ENABLED=%q\n' "${BACKUP_AUTO_ENABLED:-true}"
    if [[ -n "${BACKUP_ARCHIVE_PASSWORD:-}" ]]; then
      printf 'export BACKUP_ARCHIVE_PASSWORD=%q\n' "$BACKUP_ARCHIVE_PASSWORD"
    fi
    if [[ -n "${BACKUP_ARCHIVE_TEMP_DIR:-}" ]]; then
      printf 'export BACKUP_ARCHIVE_TEMP_DIR=%q\n' "$BACKUP_ARCHIVE_TEMP_DIR"
    fi
    if [[ -n "${RECONCILE_LOG_FILE:-}" ]]; then
      printf 'export RECONCILE_LOG_FILE=%q\n' "$RECONCILE_LOG_FILE"
    fi
    if [[ -n "${RECONCILE_STATUS_FILE:-}" ]]; then
      printf 'export RECONCILE_STATUS_FILE=%q\n' "$RECONCILE_STATUS_FILE"
    fi
    if [[ -n "${BACKUP_PROGRESS:-}" ]]; then
      printf 'export BACKUP_PROGRESS=%q\n' "$BACKUP_PROGRESS"
    fi
    if [[ -n "${BACKUP_PROGRESS_INTERVAL_SECONDS:-}" ]]; then
      printf 'export BACKUP_PROGRESS_INTERVAL_SECONDS=%q\n' "$BACKUP_PROGRESS_INTERVAL_SECONDS"
    fi
    if [[ -n "${BACKUP_STATUS_FILE:-}" ]]; then
      printf 'export BACKUP_STATUS_FILE=%q\n' "$BACKUP_STATUS_FILE"
    fi
    if [[ -n "${JOIN_USER:-}" ]]; then
      printf 'export JOIN_USER=%q\n' "$JOIN_USER"
    fi
    if [[ -n "${JOIN_PASSWORD:-}" ]]; then
      printf 'export JOIN_PASSWORD=%q\n' "$JOIN_PASSWORD"
    fi
    if [[ -n "${LDAP_URI:-}" ]]; then
      printf 'export LDAP_URI=%q\n' "$LDAP_URI"
    fi
    if [[ -n "${LDAP_BASE_DN:-}" ]]; then
      printf 'export LDAP_BASE_DN=%q\n' "$LDAP_BASE_DN"
    fi
    printf 'export TRASH_RETENTION_DAYS=%q\n' "${TRASH_RETENTION_DAYS:-7}"
    if [[ -n "${GROUP_ROOT:-}" ]]; then printf 'export GROUP_ROOT=%q\n' "$GROUP_ROOT"; fi
    if [[ -n "${PRIVATE_ROOT:-}" ]]; then printf 'export PRIVATE_ROOT=%q\n' "$PRIVATE_ROOT"; fi
    if [[ -n "${FSLOGIX_ROOT:-}" ]]; then printf 'export FSLOGIX_ROOT=%q\n' "$FSLOGIX_ROOT"; fi
  } > /app/runtime.env
  chmod 600 /app/runtime.env
}

join_domain_if_needed() {
  if net ads testjoin >/dev/null 2>&1; then
    log 'Domain join already present; skipping join.'
    return
  fi

  require_env JOIN_USER
  require_env JOIN_PASSWORD

  local join_options=()
  if [[ -n "${AD_DNS_IP:-}" ]]; then
    join_options=(--no-dns-updates "dnshostname=${AD_DNS_NAME}")
  fi

  log "Joining AD domain ${REALM}"
  if ! printf '%s\n' "$JOIN_PASSWORD" | net ads join "${join_options[@]}" -U "$JOIN_USER" -S "$DOMAIN"; then
    log 'Join using explicit server failed, retrying automatic DC discovery.'
    printf '%s\n' "$JOIN_PASSWORD" | net ads join "${join_options[@]}" -U "$JOIN_USER"
  fi
}

register_ad_dns_record() {
  if [[ -z "${AD_DNS_IP:-}" ]]; then
    log 'AD_DNS_IP is unset; skipping explicit AD DNS registration.'
    return
  fi

  log "Registering AD DNS ${AD_DNS_NAME} -> ${AD_DNS_IP}"
  net ads dns unregister -P "$AD_DNS_NAME" >/dev/null 2>&1 || true
  if ! net ads dns register -P "$AD_DNS_NAME" "$AD_DNS_IP" >/dev/null; then
    printf '[init] ERROR: failed to register AD DNS %s -> %s\n' "$AD_DNS_NAME" "$AD_DNS_IP" >&2
    return 1
  fi
}

wait_for_winbind() {
  local tries=0
  local max_tries=30
  until wbinfo -t >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [[ "$tries" -ge "$max_tries" ]]; then
      printf '[init] ERROR: winbind trust test failed after %d attempts\n' "$max_tries" >&2
      return 1
    fi
    sleep 2
  done
  return 0
}

env_is_true() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

web_should_start() {
  if [[ -n "${WEB_ENABLED:-}" ]]; then
    env_is_true "$WEB_ENABLED"
    return
  fi
  if [[ -n "${ACME_CA_SERVER:-}" ]] || \
     [[ -n "${TLS_CA_URL:-}" ]] || \
     [[ -s "${WEB_TLS_CERT_FILE:-/state/tls/web.crt}" ]]; then
    return 0
  fi
  log 'WEB_ENABLED is unset and no TLS configuration exists; web UI disabled for upgrade compatibility.'
  return 1
}

ensure_web_jwt_secret() {
  local secret_file="/state/web/jwt-secret"
  if [[ -n "${WEB_JWT_SECRET:-}" ]]; then
    export WEB_JWT_SECRET
    return
  fi

  mkdir -p /state/web
  if [[ ! -s "$secret_file" ]]; then
    umask 077
    python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > "$secret_file"
  fi
  WEB_JWT_SECRET="$(<"$secret_file")"
  export WEB_JWT_SECRET
  log 'WEB_JWT_SECRET was not provided; using a persistent generated secret.'
}

selected_tls_mode() {
  case "${WEB_TLS_MODE:-}" in
    '')
      if [[ -n "${ACME_CA_SERVER:-}" ]]; then
        printf 'acme'
      else
        printf 'ca'
      fi
      ;;
    acme|ca|files|self-signed) printf '%s' "$WEB_TLS_MODE" ;;
    *) return 1 ;;
  esac
}

ensure_acme_ca_certificates() {
  local target="$ACME_CA_CERTIFICATES"
  local download_url="${ACME_CA_CERTIFICATES_URL:-}"
  local download_tmp="${target}.download.tmp"
  local insecure=false

  if [[ ! -e "$target" ]]; then
    if [[ -z "$download_url" ]]; then
      printf '[init] ERROR: ACME_CA_CERTIFICATES does not exist and ACME_CA_CERTIFICATES_URL is unset: %s\n' "$target" >&2
      return 1
    fi
    case "$download_url" in
      https://*) ;;
      *)
        printf '[init] ERROR: ACME_CA_CERTIFICATES_URL must use https://\n' >&2
        return 1
        ;;
    esac
    if env_is_true "${ACME_CA_CERTIFICATES_INSECURE_DOWNLOAD:-false}"; then
      insecure=true
      log 'WARNING: downloading the initial ACME CA certificate bundle without TLS verification (one-time TOFU bootstrap).'
    else
      log 'Downloading the initial ACME CA certificate bundle with TLS verification.'
    fi

    mkdir -p "$(dirname "$target")"
    rm -f "$download_tmp"
    if [[ "${DOMAINSHARE_NATIVE:-false}" == "true" ]]; then
      "$DOMAINSHARE_BINARY" ca-download --state-root "$STATE_ROOT" || return 1
    elif ! python3 - "$download_url" "$download_tmp" "$insecure" <<'PY'
import ssl
import sys
import urllib.parse
import urllib.request

url, output, insecure_value = sys.argv[1:]
context = ssl.create_default_context()
if insecure_value == "true":
    context = ssl._create_unverified_context()  # noqa: SLF001
request = urllib.request.Request(url, headers={"User-Agent": "DomainShare-CA-Bootstrap/1"})
with urllib.request.urlopen(request, context=context, timeout=30) as response:
    if urllib.parse.urlsplit(response.geturl()).scheme != "https":
        raise RuntimeError("CA certificate download redirected away from HTTPS")
    payload = response.read(4 * 1024 * 1024 + 1)
if not payload or len(payload) > 4 * 1024 * 1024:
    raise RuntimeError("CA certificate download is empty or exceeds 4 MiB")
with open(output, "xb") as handle:
    handle.write(payload)
PY
    then
      rm -f "$download_tmp"
      return 1
    fi
    if ! step certificate inspect "$download_tmp" >/dev/null 2>&1; then
      printf '[init] ERROR: downloaded ACME CA certificate bundle is not valid PEM certificate data\n' >&2
      rm -f "$download_tmp"
      return 1
    fi
    chmod 0644 "$download_tmp"
    mv -f "$download_tmp" "$target"
    log "Stored the initial ACME CA certificate bundle at ${target}; it will not be downloaded again while this file exists."
  fi

  if [[ ! -s "$target" ]]; then
    printf '[init] ERROR: ACME_CA_CERTIFICATES exists but is empty: %s\n' "$target" >&2
    return 1
  fi
  if ! step certificate inspect "$target" >/dev/null 2>&1; then
    printf '[init] ERROR: ACME_CA_CERTIFICATES is not valid PEM certificate data: %s\n' "$target" >&2
    return 1
  fi
}

request_acme_certificate() {
  local cert_tmp="${WEB_TLS_CERT_FILE}.acme.tmp"
  local key_tmp="${WEB_TLS_KEY_FILE}.acme.tmp"

  rm -f "$cert_tmp" "$key_tmp"
  log "Requesting ACME HTTPS certificate for ${WEB_HOSTNAME}"
  if ! step ca certificate "$WEB_HOSTNAME" "$cert_tmp" "$key_tmp" \
    --acme "$ACME_CA_SERVER" \
    --root "$ACME_CA_CERTIFICATES" \
    --standalone \
    --http-listen "${ACME_HTTP_LISTEN:-:80}" \
    --force; then
    rm -f "$cert_tmp" "$key_tmp"
    return 1
  fi

  chmod 0600 "$key_tmp"
  chmod 0644 "$cert_tmp"
  mv -f "$key_tmp" "$WEB_TLS_KEY_FILE"
  mv -f "$cert_tmp" "$WEB_TLS_CERT_FILE"
}

configure_web_tls() {
  local tls_mode=""
  local provisioner_password_file=""

  if ! tls_mode="$(selected_tls_mode)"; then
    printf '[init] ERROR: WEB_TLS_MODE must be self-signed, acme, ca, or files\n' >&2
    return 1
  fi
  export ACTIVE_WEB_TLS_MODE="$tls_mode"
  export WEB_HOSTNAME="${WEB_HOSTNAME:-${AD_DNS_NAME}}"
  export WEB_BIND_PORT="${WEB_BIND_PORT:-8443}"
  export WEB_TLS_CERT_FILE="${WEB_TLS_CERT_FILE:-/state/tls/web.crt}"
  export WEB_TLS_KEY_FILE="${WEB_TLS_KEY_FILE:-/state/tls/web.key}"
  export STEPPATH="${TLS_CA_STATE_DIR:-/state/tls-client}"
  mkdir -p "$(dirname "$WEB_TLS_CERT_FILE")" "$(dirname "$WEB_TLS_KEY_FILE")" "$STEPPATH"

  if [[ "$tls_mode" == "self-signed" ]]; then
    return
  fi

  if [[ "$tls_mode" == "files" ]]; then
    if [[ ! -s "$WEB_TLS_CERT_FILE" || ! -s "$WEB_TLS_KEY_FILE" ]]; then
      printf '[init] ERROR: WEB_TLS_MODE=files requires %s and %s\n' "$WEB_TLS_CERT_FILE" "$WEB_TLS_KEY_FILE" >&2
      return 1
    fi
    return
  fi

  if [[ "$tls_mode" == "acme" ]]; then
    require_env ACME_CA_SERVER
    require_env ACME_CA_CERTIFICATES
    ensure_acme_ca_certificates
    if [[ ! -s "$WEB_TLS_CERT_FILE" || ! -s "$WEB_TLS_KEY_FILE" || -f "$(dirname "$WEB_TLS_CERT_FILE")/bootstrap-certificate" ]]; then
      request_acme_certificate
      rm -f "$(dirname "$WEB_TLS_CERT_FILE")/bootstrap-certificate"
    fi
    return
  fi

  if [[ ! -s "$STEPPATH/config/defaults.json" ]] || \
     env_is_true "${TLS_CA_REBOOTSTRAP:-false}"; then
    require_env TLS_CA_URL
    require_env TLS_CA_FINGERPRINT
    log "Bootstrapping CA trust for ${TLS_CA_URL}"
    step ca bootstrap --force --ca-url "$TLS_CA_URL" --fingerprint "$TLS_CA_FINGERPRINT"
  fi

  if [[ ! -s "$WEB_TLS_CERT_FILE" || ! -s "$WEB_TLS_KEY_FILE" || -f "$(dirname "$WEB_TLS_CERT_FILE")/bootstrap-certificate" ]]; then
    log "Requesting HTTPS certificate for ${WEB_HOSTNAME}"
    if [[ -n "${TLS_CA_TOKEN:-}" ]]; then
      step ca certificate "$WEB_HOSTNAME" "$WEB_TLS_CERT_FILE" "$WEB_TLS_KEY_FILE" --token "$TLS_CA_TOKEN" --force
    else
      require_env TLS_CA_PROVISIONER
      if [[ -n "${TLS_CA_PROVISIONER_PASSWORD_FILE:-}" ]]; then
        provisioner_password_file="$TLS_CA_PROVISIONER_PASSWORD_FILE"
      elif [[ -n "${TLS_CA_PROVISIONER_PASSWORD:-}" ]]; then
        provisioner_password_file="/run/tls-ca-provisioner-password"
        umask 077
        printf '%s\n' "$TLS_CA_PROVISIONER_PASSWORD" > "$provisioner_password_file"
      else
        printf '[init] ERROR: TLS_CA_TOKEN, TLS_CA_PROVISIONER_PASSWORD_FILE, or TLS_CA_PROVISIONER_PASSWORD is required for initial TLS setup\n' >&2
        return 1
      fi
      step ca certificate "$WEB_HOSTNAME" "$WEB_TLS_CERT_FILE" "$WEB_TLS_KEY_FILE" \
        --provisioner "$TLS_CA_PROVISIONER" \
        --provisioner-password-file "$provisioner_password_file" \
        --force
      if [[ "$provisioner_password_file" == "/run/tls-ca-provisioner-password" ]]; then
        rm -f "$provisioner_password_file"
      fi
    fi
  fi
  chmod 0600 "$WEB_TLS_KEY_FILE"
  chmod 0644 "$WEB_TLS_CERT_FILE"
  rm -f "$(dirname "$WEB_TLS_CERT_FILE")/bootstrap-certificate"
}

start_acme_renewal_daemon() {
  local interval="${ACME_RENEW_CHECK_SECONDS:-900}"
  if [[ ! "$interval" =~ ^[0-9]+$ ]] || (( interval < 60 )); then
    log "Invalid ACME_RENEW_CHECK_SECONDS=${interval}; using 900"
    interval=900
  fi

  log "Starting ACME certificate renewal check every ${interval} seconds"
  (
    while true; do
      sleep "$interval"
      if step certificate needs-renewal "$WEB_TLS_CERT_FILE" >/dev/null 2>&1; then
        request_acme_certificate || log 'ACME certificate renewal failed; retrying at the next interval.'
      fi
    done
  ) &
}

start_observability_services() {
  if [[ "${DOMAINSHARE_NATIVE:-false}" == "true" ]]; then
    configure_web_tls
    if env_is_true "${WEB_TLS_AUTORENEW:-true}"; then
      case "$ACTIVE_WEB_TLS_MODE" in
        acme) start_acme_renewal_daemon ;;
        ca) step ca renew --daemon --force "$WEB_TLS_CERT_FILE" "$WEB_TLS_KEY_FILE" & ;;
      esac
    fi
    return
  fi

  log 'Starting Samba audit collector'
  python3 /app/audit_collector.py &

  if [[ "${DOMAINSHARE_SUPERVISED:-false}" == "true" ]]; then
    configure_web_tls
    if env_is_true "${WEB_TLS_AUTORENEW:-true}"; then
      case "$ACTIVE_WEB_TLS_MODE" in
        acme) start_acme_renewal_daemon ;;
        ca) step ca renew --daemon --force "$WEB_TLS_CERT_FILE" "$WEB_TLS_KEY_FILE" & ;;
      esac
    fi
    log 'Starting document search and OCR worker'
    python3 /app/document_index.py &
  elif web_should_start; then
    ensure_web_jwt_secret
    configure_web_tls
    unset TLS_CA_PROVISIONER_PASSWORD TLS_CA_TOKEN
    if env_is_true "${WEB_TLS_AUTORENEW:-true}"; then
      case "$ACTIVE_WEB_TLS_MODE" in
        acme) start_acme_renewal_daemon ;;
        ca)
          log 'Starting CA certificate renewal daemon'
          step ca renew --daemon --force "$WEB_TLS_CERT_FILE" "$WEB_TLS_KEY_FILE" &
          ;;
      esac
    fi
    log 'Starting document search and OCR worker'
    (
      while true; do
        python3 /app/document_index.py || log 'Document worker failed'
        log 'Document worker stopped; restarting in two seconds'
        sleep 2
      done
    ) &
    log "Starting web UI for https://${WEB_HOSTNAME}"
    python3 /app/web_ui.py &
  else
    log 'WEB_ENABLED is false; web UI disabled'
  fi
}

install_cron_job() {
  cat > /etc/cron.d/reconcile-shares <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * root source /app/runtime.env && RECONCILE_TRIGGER=automatic /usr/bin/python3 /app/reconcile_shares.py
17 * * * * root source /app/runtime.env && /usr/bin/python3 /app/trash.py --cleanup
EOF

  if [[ "${DOMAINSHARE_SUPERVISED:-false}" != "true" ]] && [[ -n "${BACKUP_DESTINATION:-}" ]] && env_is_true "${BACKUP_AUTO_ENABLED:-true}"; then
    cat >> /etc/cron.d/reconcile-shares <<EOF
0 ${BACKUP_START_HOUR} * * * root source /app/runtime.env && BACKUP_TRIGGER=automatic /usr/bin/python3 /app/backup_to_destination.py
EOF
  fi

  chmod 0644 /etc/cron.d/reconcile-shares
}

run_root="${DOMAINSHARE_RUN_ROOT:-/run}"
if [[ "${DOMAINSHARE_NATIVE:-false}" == "true" ]]; then
  : "${DOMAINSHARE_BINARY:?Start native mode with domainshare supervise --native}"
  : "${STATE_ROOT:?The supervisor must supply STATE_ROOT}"
  state_exports="$("$DOMAINSHARE_BINARY" export-shell --state-root "$STATE_ROOT")"
  source /dev/stdin <<<"$state_exports"
  unset state_exports
elif [[ "${DOMAINSHARE_SUPERVISED:-false}" == "true" ]]; then
  source <(python3 /app/configuration.py export-shell)
fi
if [[ "${1:-}" == "--configure-tls" ]]; then
  configure_web_tls
  exit 0
fi
if [[ "${1:-}" == "--bootstrap-domain" ]]; then
  export DOMAIN_USERS_SID="${DOMAIN_USERS_SID:-S-1-5-32-545}"
  export DOMAIN_ADMINS_SID="${DOMAIN_ADMINS_SID:-S-1-5-32-544}"
fi
require_env REALM
require_env WORKGROUP
require_env DOMAIN
require_env DOMAIN_USERS_SID
require_env DOMAIN_ADMINS_SID

export REALM WORKGROUP DOMAIN
export BACKUP_START_HOUR="$(derive_backup_start_hour)"
export FSLOGIX_GROUP_SID="${FSLOGIX_GROUP_SID:-${DOMAIN_USERS_SID}}"
export DOMAIN_USERS_GROUP="${DOMAIN_USERS_SID}"
export DOMAIN_ADMINS_GROUP="${DOMAIN_ADMINS_SID}"
export FSLOGIX_GROUP="${FSLOGIX_GROUP_SID}"
if [[ -n "${JOIN_USER:-}" ]]; then
  export JOIN_USER
fi
if [[ -n "${JOIN_PASSWORD:-}" ]]; then
  export JOIN_PASSWORD
fi

mkdir -p /data/private /data/fslogix /data/groups/data /data/groups/archive /state /var/log/samba
touch /var/log/reconcile.log /var/log/backup.log

append_winbind_to_nss
require_vfs_modules
derive_netbios_name
derive_ad_dns_name
render_krb5_conf
render_smb_conf
join_domain_if_needed
ensure_machine_keytab

log 'Starting winbindd'
winbindd -F --no-process-group &
winbind_pid=$!

wait_for_winbind
touch "$run_root/domainshare-domain-ready"
if [[ "${1:-}" == "--bootstrap-domain" ]]; then
  log 'Domain joined; waiting for web setup to select groups.'
  wait "$winbind_pid"
  exit "$?"
fi

register_ad_dns_record
resolve_share_groups_from_sids
render_smb_conf
if [[ "${DOMAINSHARE_NATIVE:-false}" == "true" ]]; then
  log 'Running startup reconciliation'
  RECONCILE_TRIGGER=startup "$DOMAINSHARE_BINARY" reconcile --state-root "$STATE_ROOT"

  log 'Preparing seven-day trash repositories'
  "$DOMAINSHARE_BINARY" trash-cleanup --state-root "$STATE_ROOT"
else
  write_runtime_env_file

  log 'Running startup reconciliation'
  RECONCILE_TRIGGER=startup python3 /app/reconcile_shares.py

  log 'Preparing seven-day trash repositories'
  python3 /app/trash.py --cleanup
fi

start_observability_services

if [[ -n "${BACKUP_DESTINATION:-}" ]] && env_is_true "${BACKUP_AUTO_ENABLED:-true}"; then
  log "Backups enabled: automatic daily run at ${BACKUP_START_HOUR}:00 UTC and manual runs available."
elif [[ -n "${BACKUP_DESTINATION:-}" ]]; then
  log 'Automatic backups disabled; manual runs remain available through the web UI and CLI.'
else
  log 'BACKUP_DESTINATION is unset; backups disabled'
fi

if [[ "${DOMAINSHARE_NATIVE:-false}" == "true" ]]; then
  log 'Starting smbd'
  smbd -F --no-process-group &
  smbd_pid=$!

  for (( attempt=0; attempt<30; attempt++ )); do
    kill -0 "$smbd_pid" "$winbind_pid" || exit 1
    if timeout 2 smbcontrol smbd ping >/dev/null 2>&1; then
      touch "$run_root/domainshare-services-ready"
      wait -n "$winbind_pid" "$smbd_pid"
      exit "$?"
    fi
    sleep 1
  done

  log 'smbd did not become ready'
  exit 1
fi

install_cron_job

log 'Starting cron daemon'
cron -f &

log 'Starting smbd in foreground'
touch "$run_root/domainshare-services-ready"
exec smbd -F --no-process-group
