FROM alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

RUN apk add --no-cache ca-certificates nftables python3 \
    && cp /bin/busybox /bin/sh.sendbox \
    && mv -f /bin/sh.sendbox /bin/sh \
    && cp /usr/bin/python3.12 /usr/local/bin/sendbox-dns-python

COPY probe.py trace.py /opt/sendbox-dns/
