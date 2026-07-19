# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM rust:1.93.1-alpine3.23@sha256:4fec02de605563c297c78a31064c8335bc004fa2b0bf406b1b99441da64e2d2d AS toolchain

ARG TARGETARCH

RUN apk add --no-cache \
        binutils=2.45.1-r0 \
        file=5.46-r2 \
        musl-dev=1.2.5-r23

RUN case "$TARGETARCH" in \
        amd64) target="x86_64-unknown-linux-musl" ;; \
        arm64) target="aarch64-unknown-linux-musl" ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && test "$(rustc -vV | sed -n 's/^host: //p')" = "$target" \
    && printf '%s\n' "$target" >/opt/target-triple

FROM toolchain AS audit-tool
RUN cargo install cargo-audit --version 0.22.2 --locked

FROM toolchain AS source
WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates crates
COPY config config
COPY guest/sendbox-guest guest/sendbox-guest
COPY test-fixtures test-fixtures
RUN chmod +x guest/sendbox-guest/scripts/verify-static.sh

ENV CARGO_INCREMENTAL=0
ENV SOURCE_DATE_EPOCH=0
ENV RUSTFLAGS="-Dwarnings --remap-path-prefix=/workspace=."

FROM source AS quality
COPY --from=audit-tool /usr/local/cargo/bin/cargo-audit /usr/local/cargo/bin/cargo-audit
RUN target="$(cat /opt/target-triple)" \
    && cargo fmt --all --check \
    && cargo clippy --locked --workspace --all-targets --all-features --target "$target" -- -D warnings \
    && cargo test --locked --workspace --all-features --target "$target" \
    && cargo audit --deny warnings \
    && touch /quality-ok

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
