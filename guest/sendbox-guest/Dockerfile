# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM rust:1.93.1-alpine3.23@sha256:4fec02de605563c297c78a31064c8335bc004fa2b0bf406b1b99441da64e2d2d AS toolchain

ARG TARGETARCH

RUN apk add --no-cache \
        binutils=2.45.1-r0 \
        curl=8.20.0-r0 \
        file=5.46-r2 \
        g++=15.2.0-r2 \
        gperf=3.3-r0 \
        linux-headers=6.16.12-r0 \
        make=4.4.1-r3 \
        pkgconf=2.5.1-r0 \
        musl-dev=1.2.5-r23

RUN case "$TARGETARCH" in \
        amd64) target="x86_64-unknown-linux-musl" ;; \
        arm64) target="aarch64-unknown-linux-musl" ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && test "$(rustc -vV | sed -n 's/^host: //p')" = "$target" \
    && printf '%s\n' "$target" >/opt/target-triple

FROM toolchain AS libseccomp
RUN curl -fsSL \
        https://github.com/seccomp/libseccomp/releases/download/v2.6.0/libseccomp-2.6.0.tar.gz \
        -o /tmp/libseccomp.tar.gz \
    && echo "83b6085232d1588c379dc9b9cae47bb37407cf262e6e74993c61ba72d2a784dc  /tmp/libseccomp.tar.gz" \
        | sha256sum -c - \
    && tar -xzf /tmp/libseccomp.tar.gz -C /tmp \
    && cd /tmp/libseccomp-2.6.0 \
    && ./configure --prefix=/opt/libseccomp --disable-shared --enable-static \
    && make -j2 \
    && make install \
    && test -f /opt/libseccomp/lib/libseccomp.a \
    && rm -rf /tmp/libseccomp.tar.gz /tmp/libseccomp-2.6.0

FROM toolchain AS audit-tool
RUN cargo install cargo-audit --version 0.22.2 --locked

FROM toolchain AS source
WORKDIR /workspace
COPY --from=libseccomp /opt/libseccomp /opt/libseccomp
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates crates
COPY config config
COPY guest/sendbox-guest guest/sendbox-guest
COPY test-fixtures test-fixtures
RUN chmod +x guest/sendbox-guest/scripts/verify-static.sh

ENV CARGO_INCREMENTAL=0
ENV LIBSECCOMP_STATIC=1
ENV PKG_CONFIG_ALL_STATIC=1
ENV PKG_CONFIG_PATH=/opt/libseccomp/lib/pkgconfig
ENV SOURCE_DATE_EPOCH=0
ENV RUSTFLAGS="-Dwarnings --remap-path-prefix=/workspace=."

FROM source AS quality
COPY --from=audit-tool /usr/local/cargo/bin/cargo-audit /usr/local/cargo/bin/cargo-audit
RUN adduser -D -u 10001 quality \
    && chown -R quality:quality /workspace
ENV CARGO_HOME=/home/quality/.cargo
USER quality
RUN target="$(cat /opt/target-triple)" \
    && cargo fmt --all --check \
    && cargo clippy --locked -p sendbox-guest --all-targets --all-features --target "$target" -- -D warnings \
    && cargo test --locked -p sendbox-guest --all-targets --all-features --target "$target" \
    && cargo audit --deny warnings \
    && touch /tmp/quality-ok

FROM source AS release
RUN target="$(cat /opt/target-triple)" \
    && cargo build --locked --release --target "$target" -p sendbox-guest \
    && mkdir -p /out \
    && cp "target/$target/release/sendbox-guest" /out/ \
    && guest/sendbox-guest/scripts/verify-static.sh \
        /out/sendbox-guest \
        /out/static-link-proof.txt \
    && sha256sum /out/sendbox-guest >/out/sendbox-guest.sha256

FROM scratch AS artifact
COPY --from=release /out/ /
