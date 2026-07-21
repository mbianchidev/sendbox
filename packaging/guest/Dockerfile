# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM rust:1.93.1-alpine3.23@sha256:4fec02de605563c297c78a31064c8335bc004fa2b0bf406b1b99441da64e2d2d AS toolchain

ARG TARGETARCH

RUN apk add --no-cache \
        binutils=2.45.1-r0 \
        bpftool=6.19.14-r0 \
        clang21=21.1.2-r2 \
        curl=8.20.0-r0 \
        elfutils-dev=0.194-r0 \
        file=5.46-r2 \
        g++=15.2.0-r2 \
        gperf=3.3-r0 \
        libbpf-dev=1.6.2-r0 \
        linux-headers=6.16.12-r0 \
        llvm21=21.1.2-r1 \
        make=4.4.1-r3 \
        musl-dev=1.2.5-r23 \
        openssl-dev=3.5.7-r0 \
        pkgconf=2.5.1-r0 \
        tar=1.35-r4 \
        zlib-dev=1.3.2-r0 \
        zlib-static=1.3.2-r0 \
        zstd-dev=1.5.7-r2 \
        zstd-static=1.5.7-r2

RUN ar d /usr/lib/libelf.a crc32.o \
    && ranlib /usr/lib/libelf.a \
    && ! nm -g /usr/lib/libelf.a | grep -q ' T crc32$'

RUN case "$TARGETARCH" in \
        amd64) \
            target="x86_64-unknown-linux-musl"; \
            rust_arch="x86_64"; \
            btf_arch="x86_64"; \
            btf_sha="d00037ea649e2ac209267619c88dceecc31f5bbf4ef9f2d139dddeabc2c0f2a6" ;; \
        arm64) \
            target="aarch64-unknown-linux-musl"; \
            rust_arch="aarch64"; \
            btf_arch="arm64"; \
            btf_sha="cdd9e65811a4de0e98012dd1c59ea3a90aa57a27b6b1896d2abf83f0713d0138" ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && test "$(rustc -vV | sed -n 's/^host: //p')" = "$target" \
    && mkdir -p "/opt/vmlinux/$btf_arch" \
    && curl -fsSL \
        "https://raw.githubusercontent.com/aquasecurity/btfhub-archive/abbcdfab668b9a346a24cb0829f1cfbb80bc51db/ubuntu/20.04/$btf_arch/5.8.0-63-generic.btf.tar.xz" \
        -o /tmp/vmlinux.btf.tar.xz \
    && echo "$btf_sha  /tmp/vmlinux.btf.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/vmlinux.btf.tar.xz -C /tmp \
    && bpftool btf dump file /tmp/5.8.0-63-generic.btf format c \
        >"/opt/vmlinux/$btf_arch/vmlinux.h" \
    && cp /tmp/5.8.0-63-generic.btf "/opt/vmlinux/$btf_arch/vmlinux.btf" \
    && printf '%s\n' "$target" >/opt/target-triple \
    && printf '%s\n' "$rust_arch" >/opt/rust-architecture \
    && printf '%s\n' "$btf_arch" >/opt/btf-architecture \
    && sha256sum "/opt/vmlinux/$btf_arch/vmlinux.h" >/opt/vmlinux.sha256 \
    && rm -f /tmp/vmlinux.btf.tar.xz /tmp/5.8.0-63-generic.btf

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
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY .cargo .cargo
COPY crates crates
COPY config config
COPY fuzz fuzz
COPY guest guest
COPY native native
COPY test-fixtures test-fixtures
COPY packaging/guest packaging/guest
RUN chmod +x guest/sendbox-guest/scripts/verify-static.sh packaging/guest/verify-bpf.sh

ENV CARGO_INCREMENTAL=0
ENV LIBBPF_SYS_EXTRA_CFLAGS="-Wno-error=deprecated-declarations"
ENV SOURCE_DATE_EPOCH=0

FROM source AS bpf
RUN arch="$(cat /opt/btf-architecture)" \
    && target_arch="$([ "$arch" = x86_64 ] && echo x86 || echo arm64)" \
    && mkdir -p /out \
    && clang-21 \
        -target bpfel \
        -D__BPF_TRACING__ \
        "-D__TARGET_ARCH_${target_arch}" \
        -O2 \
        -g \
        -Wall \
        -Wextra \
        -Werror \
        -Wconversion \
        -Wformat=2 \
        -Wshadow \
        -Wstrict-prototypes \
        -fno-stack-protector \
        -I "/opt/vmlinux/$arch" \
        -I /usr/include \
        -c native/bpf/observe.bpf.c \
        -o /out/observe.bpf.o \
    && packaging/guest/verify-bpf.sh /out/observe.bpf.o \
    && bpftool gen min_core_btf \
        "/opt/vmlinux/$arch/vmlinux.btf" \
        /out/min-core.btf \
        /out/observe.bpf.o \
    && test -s /out/min-core.btf \
    && sha256sum /out/min-core.btf >/out/core-relocation.sha256 \
    && rm /out/min-core.btf \
    && cp /opt/vmlinux.sha256 /out/

FROM source AS quality
COPY --from=audit-tool /usr/local/cargo/bin/cargo-audit /usr/local/cargo/bin/cargo-audit
COPY --from=bpf /out/observe.bpf.o /tmp/observe.bpf.o
RUN target="$(cat /opt/target-triple)" \
    && cargo fmt --all --check \
    && cargo clippy --locked -p sendbox-bpf -p sendbox-bundle -p sendbox-guest \
        --all-targets --all-features --target "$target" -- -D warnings \
    && cargo test --locked -p sendbox-bpf -p sendbox-bundle -p sendbox-guest \
        --all-targets --all-features --target "$target" \
    && cargo check --locked --manifest-path fuzz/bpf/Cargo.toml --bins \
    && cargo audit --deny warnings \
    && touch /quality-ok

FROM source AS release
COPY --from=bpf /out /bpf
COPY --from=libseccomp /opt/libseccomp /opt/libseccomp
ENV LIBSECCOMP_STATIC=1
ENV PKG_CONFIG_ALL_STATIC=1
ENV PKG_CONFIG_PATH=/opt/libseccomp/lib/pkgconfig
RUN target="$(cat /opt/target-triple)" \
    && cargo build --locked --release --target "$target" \
        -p sendbox-guest \
        -p sendbox-exec \
        -p sendbox-bundle \
        --bins \
    && mkdir -p /release \
    && cp "target/$target/release/sendbox-guest" /release/ \
    && cp "target/$target/release/sendbox-exec-launcher" /release/ \
    && cp "target/$target/release/sendbox-bundle" /release/ \
    && guest/sendbox-guest/scripts/verify-static.sh \
        /release/sendbox-guest /release/sendbox-guest.static.txt \
    && guest/sendbox-guest/scripts/verify-static.sh \
        /release/sendbox-exec-launcher /release/sendbox-exec-launcher.static.txt

FROM release AS bundle
ARG RELEASE_SEQUENCE=1
ARG MINIMUM_ACCEPTED_SEQUENCE=1
ARG HOST_VERSION=0.1.0
ARG GUEST_VERSION=0.1.0
ARG TRUST_ROOT_ID=external-release-root
RUN --mount=type=secret,id=release_signing_key,required=true \
    architecture="$(cat /opt/rust-architecture)" \
    && /release/sendbox-bundle public-key \
        --signing-key /run/secrets/release_signing_key \
        --output /tmp/release-public.key \
    && /release/sendbox-bundle stage \
        --output /bundle \
        --guest /release/sendbox-guest \
        --launcher /release/sendbox-exec-launcher \
        --bpf /bpf/observe.bpf.o \
        --signing-key /run/secrets/release_signing_key \
        --architecture "$architecture" \
        --trust-root-id "$TRUST_ROOT_ID" \
        --release-sequence "$RELEASE_SEQUENCE" \
        --minimum-accepted-sequence "$MINIMUM_ACCEPTED_SEQUENCE" \
        --host-version "$HOST_VERSION" \
        --guest-version "$GUEST_VERSION" \
        --uid 0 \
        --gid 0 \
    && /release/sendbox-bundle verify \
        --root /bundle \
        --public-key /tmp/release-public.key \
        --architecture "$architecture" \
        --trust-root-id "$TRUST_ROOT_ID" \
        --host-version "$HOST_VERSION" \
        --guest-version "$GUEST_VERSION" \
        --minimum-release-sequence "$MINIMUM_ACCEPTED_SEQUENCE"

FROM bundle AS rootfs
RUN mkdir -p /out \
    && tar \
        --sort=name \
        --mtime="@0" \
        --owner=0 \
        --group=0 \
        --numeric-owner \
        --format=ustar \
        -cf /out/sendbox-guest-rootfs.tar \
        -C /bundle . \
    && cd /out \
    && sha256sum sendbox-guest-rootfs.tar >sendbox-guest-rootfs.tar.sha256 \
    && cp /release/*.static.txt /out/ \
    && cp /bpf/vmlinux.sha256 /out/ \
    && cp /bpf/core-relocation.sha256 /out/ \
    && cp /bundle/manifest.json /bundle/manifest.sig /tmp/release-public.key /out/ \
    && cp /bundle/share/sendbox/inventory.json /bundle/share/sendbox/sbom.spdx.json /out/

FROM scratch AS image
COPY --from=bundle /bundle/ /opt/sendbox/

FROM scratch AS artifact
COPY --from=rootfs /out/ /
