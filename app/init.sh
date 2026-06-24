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
  for module in acl_xattr full_audit; do
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
  local raw_name="${NETBIOS_NAME:-ADSAMBAFSRV}"
  local upper_name="${raw_name^^}"
  local cleaned_name
  cleaned_name="$(printf '%s' "$upper_name" | tr -cd 'A-Z0-9')"

  if [[ -z "$cleaned_name" ]]; then
    cleaned_name="SAMBAFS"
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

install_cron_job() {
  cat > /etc/cron.d/reconcile-shares <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * root source /app/runtime.env && /usr/bin/python3 /app/reconcile_shares.py >> /var/log/reconcile.log 2>&1
EOF

  if [[ -n "${BACKUP_DESTINATION:-}" ]]; then
    cat >> /etc/cron.d/reconcile-shares <<EOF
0 ${BACKUP_START_HOUR} * * * root source /app/runtime.env && /usr/bin/python3 /app/backup_to_destination.py >> /var/log/backup.log 2>&1
EOF
  fi

  chmod 0644 /etc/cron.d/reconcile-shares
}

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

wait_for_winbind

register_ad_dns_record
resolve_share_groups_from_sids
render_smb_conf
write_runtime_env_file

log 'Running startup reconciliation'
python3 /app/reconcile_shares.py

if [[ -n "${BACKUP_DESTINATION:-}" ]]; then
  log "Backups enabled: daily at ${BACKUP_START_HOUR}:00 (container local time)."
else
  log 'BACKUP_DESTINATION is unset; scheduled backup disabled'
fi

install_cron_job

log 'Starting cron daemon'
cron -f &

log 'Starting smbd in foreground'
exec smbd -F --no-process-group
