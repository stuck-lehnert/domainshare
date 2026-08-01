FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends p7zip-full rsync tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /backup

COPY dev/backup-entrypoint.sh /usr/local/bin/preview-backup-entrypoint
RUN chmod +x /usr/local/bin/preview-backup-entrypoint

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/preview-backup-entrypoint"]
