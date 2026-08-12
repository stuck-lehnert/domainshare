FROM docker.io/library/debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        dnsutils \
        krb5-user \
        ldb-tools \
        samba \
        samba-ad-dc \
        samba-ad-provision \
        smbclient \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY dev/ad-entrypoint.sh /usr/local/bin/preview-ad-entrypoint
COPY dev/preview-client.sh /usr/local/bin/preview-client
COPY dev/seed-files.sh /usr/local/bin/preview-seed-files

RUN chmod +x \
        /usr/local/bin/preview-ad-entrypoint \
        /usr/local/bin/preview-client \
        /usr/local/bin/preview-seed-files

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/preview-ad-entrypoint"]
