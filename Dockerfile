FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

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
        samba \
        samba-vfs-modules \
        sqlite3 \
        tini \
        winbind \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app /data/private /data/public /data/fslogix /data/groups /state /etc/samba/generated

COPY app/reconcile_shares.py /app/reconcile_shares.py
COPY app/init.sh /app/init.sh
COPY etc/samba/smb.conf /app/smb.conf.template

RUN chmod +x /app/init.sh /app/reconcile_shares.py \
    && touch /etc/samba/generated/shares.conf

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/app/init.sh"]
