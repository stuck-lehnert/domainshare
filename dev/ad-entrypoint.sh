#!/usr/bin/env bash
set -Eeuo pipefail

log() {
  printf '[preview-ad] %s\n' "$*"
}

require_env() {
  local name=$1
  if [[ -z ${!name:-} ]]; then
    printf '[preview-ad] ERROR: missing %s\n' "$name" >&2
    exit 1
  fi
}

for name in AD_REALM AD_DOMAIN AD_DNS_DOMAIN AD_BASE_DN AD_ADMIN_PASSWORD \
  AD_USER_PASSWORD AD_WEB_ADMIN_USER AD_WEB_ADMIN_PASSWORD \
  DEV_CA_IP DEV_BACKUP_IP DEV_FILESERVER_IP; do
  require_env "$name"
done

if [[ ! -s /var/lib/samba/private/sam.ldb ]]; then
  log "Provisioning disposable ${AD_REALM} domain"
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --server-role=dc \
    --use-rfc2307 \
    --dns-backend=SAMBA_INTERNAL \
    --realm="$AD_REALM" \
    --domain="$AD_DOMAIN" \
    --adminpass="$AD_ADMIN_PASSWORD"
fi

ln -sf /var/lib/samba/private/krb5.conf /etc/krb5.conf

log 'Starting Samba AD DC'
samba -i --no-process-group &
samba_pid=$!

stop_samba() {
  kill "$samba_pid" >/dev/null 2>&1 || true
  wait "$samba_pid" 2>/dev/null || true
}
trap stop_samba EXIT INT TERM HUP

ready=0
for _ in $(seq 1 90); do
  if samba-tool domain info 127.0.0.1 >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ $ready != 1 ]]; then
  printf '[preview-ad] ERROR: domain controller did not become ready\n' >&2
  exit 1
fi

ensure_user() {
  local user=$1
  local password=$2
  local given=$3
  local surname=$4
  if ! samba-tool user show "$user" >/dev/null 2>&1; then
    samba-tool user create "$user" "$password" \
      --given-name="$given" --surname="$surname" >/dev/null
  fi
}

ensure_group() {
  local group=$1
  if ! samba-tool group show "$group" >/dev/null 2>&1; then
    samba-tool group add "$group" >/dev/null
  fi
}

add_members() {
  local group=$1
  local members=$2
  samba-tool group addmembers "$group" "$members" >/dev/null 2>&1 || true
}

set_display_name() {
  local group=$1
  local display_name=$2
  ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<EOF
dn: CN=${group},CN=Users,${AD_BASE_DN}
changetype: modify
replace: displayName
displayName: ${display_name}
EOF
}

log 'Seeding users and nested file-share groups'
ensure_user alice "$AD_USER_PASSWORD" Alice Adams
ensure_user bob "$AD_USER_PASSWORD" Bob Brown
ensure_user carol "$AD_USER_PASSWORD" Carol Clark
ensure_user dave "$AD_USER_PASSWORD" Dave Davis
ensure_user eve "$AD_USER_PASSWORD" Eve Evans
ensure_user "$AD_WEB_ADMIN_USER" "$AD_WEB_ADMIN_PASSWORD" Preview Administrator

for group in Finance_Analysts Engineering_Leads FS_Finance FS_Engineering FS_Projects; do
  ensure_group "$group"
done

set_display_name Finance_Analysts 'Finance Analysts'
set_display_name Engineering_Leads 'Engineering Leads'
set_display_name FS_Finance Finance
set_display_name FS_Engineering Engineering
set_display_name FS_Projects Projects

add_members Finance_Analysts alice
add_members FS_Finance 'Finance_Analysts,bob'
add_members Engineering_Leads carol
add_members FS_Engineering 'Engineering_Leads,dave'
add_members FS_Projects 'FS_Finance,FS_Engineering,eve'
add_members 'Domain Admins' "$AD_WEB_ADMIN_USER"

add_dns_record() {
  local name=$1
  local address=$2
  samba-tool dns add 127.0.0.1 "$AD_DNS_DOMAIN" "$name" A "$address" \
    -U "Administrator%${AD_ADMIN_PASSWORD}" >/dev/null 2>&1 || true
}

add_dns_record ca "$DEV_CA_IP"
add_dns_record backup "$DEV_BACKUP_IP"
add_dns_record files "$DEV_FILESERVER_IP"

domain_sid=$(ldbsearch -H /var/lib/samba/private/sam.ldb \
  -b "$AD_BASE_DN" -s base objectSid 2>/dev/null \
  | sed -n 's/^objectSid: //p' | head -n1)
if [[ -z $domain_sid ]]; then
  printf '[preview-ad] ERROR: unable to determine domain SID\n' >&2
  exit 1
fi
printf '%s\n' "$domain_sid" > /run/domain-sid
touch /run/preview-ready
log "Ready: ${AD_DOMAIN} (${domain_sid})"

wait "$samba_pid"
