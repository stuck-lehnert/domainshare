FROM docker.io/library/debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        dnsutils \
        krb5-user \
        ldb-tools \
        python3-pil \
        python3-reportlab \
        fonts-urw-base35 \
        samba \
        samba-ad-dc \
        samba-ad-provision \
        smbclient \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Rootless Podman maps 65,536 IDs. Keep this disposable DC's internal idmap
# inside that namespace; production AD domains must use their normal range.
RUN sed -i \
        -e 's/lowerBound: 3000000/lowerBound: 10000/' \
        -e 's/upperBound: 4000000/upperBound: 60000/' \
        /usr/share/samba/setup/idmap_init.ldif

COPY dev/ad-entrypoint.sh /usr/local/bin/preview-ad-entrypoint
COPY dev/preview-client.sh /usr/local/bin/preview-client
COPY dev/seed-files.sh /usr/local/bin/preview-seed-files

RUN chmod +x \
        /usr/local/bin/preview-ad-entrypoint \
        /usr/local/bin/preview-client \
        /usr/local/bin/preview-seed-files

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/preview-ad-entrypoint"]
