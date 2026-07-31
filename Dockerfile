FROM smallstep/step-cli:0.30.2 AS step-cli

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        acl \
        cron \
        gettext-base \
        krb5-user \
        ldap-utils \
        libnss-winbind \
        libpam-winbind \
        python3 \
        rclone \
        rsync \
        samba \
        samba-vfs-modules \
        sqlite3 \
        tini \
        winbind \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app /data/private /data/fslogix /data/groups/data /data/groups/archive /state
COPY --from=step-cli /usr/local/bin/step /usr/local/bin/step

COPY app/reconcile_shares.py /app/reconcile_shares.py
COPY app/backup_to_destination.py /app/backup_to_destination.py
COPY app/audit_collector.py /app/audit_collector.py
COPY app/web_ui.py /app/web_ui.py
COPY app/web /app/web
COPY app/init.sh /app/init.sh
COPY etc/samba/smb.conf /app/smb.conf.template

RUN chmod +x /app/init.sh /app/reconcile_shares.py /app/backup_to_destination.py \
        /app/audit_collector.py /app/web_ui.py \
    && true

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/init.sh"]
