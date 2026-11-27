FROM docker.io/smallstep/step-cli:0.31.0 AS step-cli

FROM docker.io/library/golang:1.25-bookworm AS go-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN mkdir /out \
    && go build -trimpath -o /out/ ./cmd/... \
    && cc -std=gnu11 -O2 -Wall -Wextra -Werror \
        "-DSAMBA_PRIVATE_DIR=\"/usr/lib/$(gcc -print-multiarch)/samba\"" \
        internal/sambaacl/helper/main.c -o /out/domainshare-sambaacl -ldl \
    && go clean -cache -modcache

FROM docker.io/library/debian:12-slim AS runtime

LABEL org.opencontainers.image.title="DomainShare"

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        acl \
        gettext-base \
        krb5-user \
        ldap-utils \
        libnss-winbind \
        libpam-winbind \
        libtiff-tools \
        python3 \
        python3-samba \
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

RUN useradd --system --no-create-home --shell /usr/sbin/nologin document-ocr \
    && sed -ri '/^passwd:/ { /winbind/! s/$/ winbind/ }; /^group:/ { /winbind/! s/$/ winbind/ }' /etc/nsswitch.conf

RUN mkdir -p /app /data/private /data/fslogix /data/groups/data /data/groups/archive /state
COPY --from=step-cli /usr/local/bin/step /usr/local/bin/step
COPY --from=go-build /out/domainshare /usr/local/bin/domainshare
COPY --from=go-build /out/domainshare-backup /usr/local/bin/domainshare-backup
COPY --from=go-build /out/domainshare-trash /usr/local/bin/domainshare-trash
COPY --from=go-build /out/domainshare-sambaacl /usr/local/libexec/domainshare-sambaacl
COPY app/web /app/web
COPY --chmod=755 app/init.sh /app/init.sh
COPY etc/samba/smb.conf /app/smb.conf.template

ENTRYPOINT ["/usr/bin/tini", "-s", "--"]

# Retain the previous backend only for migration tests and explicit rollback.
FROM runtime AS python-compat

RUN apt-get update \
    && apt-get install -y --no-install-recommends cron python3-pil \
    && rm -rf /var/lib/apt/lists/*

COPY app/reconcile_shares.py /app/reconcile_shares.py
COPY app/backup_to_destination.py /app/backup_to_destination.py
COPY app/audit_policy.py /app/audit_policy.py
COPY app/state_db.py /app/state_db.py
COPY app/access_control.py /app/access_control.py
COPY app/account_policy.py /app/account_policy.py
COPY app/audit_store.py /app/audit_store.py
COPY app/audit_collector.py /app/audit_collector.py
COPY app/trash.py /app/trash.py
COPY app/agent_api.py /app/agent_api.py
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
CMD ["python3", "/app/entrypoint.py"]

FROM runtime AS domainshare
CMD ["/usr/local/bin/domainshare", "supervise", "--native"]
