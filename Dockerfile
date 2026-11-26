FROM docker.io/smallstep/step-cli:0.31.0 AS step-cli

FROM docker.io/library/debian:12-slim

LABEL org.opencontainers.image.title="DomainShare"

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
        python3-samba \
        python3-pil \
        ocrmypdf \
        poppler-utils \
        tesseract-ocr-deu \
        tesseract-ocr-eng \
        p7zip-full \
        rclone \
        rsync \
        samba \
        samba-vfs-modules \
        sqlite3 \
        tini \
        winbind \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin document-ocr

RUN mkdir -p /app /data/private /data/fslogix /data/groups/data /data/groups/archive /state
COPY --from=step-cli /usr/local/bin/step /usr/local/bin/step

COPY app/reconcile_shares.py /app/reconcile_shares.py
COPY app/backup_to_destination.py /app/backup_to_destination.py
COPY app/audit_policy.py /app/audit_policy.py
COPY app/state_db.py /app/state_db.py
COPY app/access_control.py /app/access_control.py
COPY app/account_policy.py /app/account_policy.py
COPY app/audit_store.py /app/audit_store.py
COPY app/audit_collector.py /app/audit_collector.py
COPY app/trash.py /app/trash.py
COPY app/web_ui.py /app/web_ui.py
COPY app/web_security.py /app/web_security.py
COPY app/configuration.py app/backup_keys.py app/tls_configuration.py app/entrypoint.py app/run_service.py app/healthcheck.py /app/
COPY app/http_setup.py /app/http_setup.py
COPY app/restore_backup.py /app/restore_backup.py
COPY app/vendor /app/vendor
COPY app/document_types.py /app/document_types.py
COPY app/documents.py /app/documents.py
COPY app/document_search.py /app/document_search.py
COPY app/document_index.py /app/document_index.py
COPY app/extract_document.py /app/extract_document.py
COPY app/web /app/web
COPY app/init.sh /app/init.sh
COPY etc/samba/smb.conf /app/smb.conf.template

RUN chmod +x /app/init.sh /app/reconcile_shares.py /app/backup_to_destination.py \
        /app/audit_collector.py /app/web_ui.py \
    && true

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/app/entrypoint.py"]
