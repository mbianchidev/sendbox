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
        libbpf-dev=1.6.2-r0 \
        linux-headers=6.16.12-r0 \
        llvm21=21.1.2-r1 \
        make=4.4.1-r3 \
        musl-dev=1.2.5-r23 \
        openssl-dev=3.5.7-r0 \
        pkgconf=2.5.1-r0 \
        xz=5.8.3-r0 \
        zlib-dev=1.3.2-r0 \
        zlib-static=1.3.2-r0 \
        zstd-dev=1.5.7-r2 \
        zstd-static=1.5.7-r2

# Alpine libelf ships a fallback zlib-compatible crc32 object. Remove that
# single-symbol fallback so the pinned libz archive is the sole provider.
RUN ar d /usr/lib/libelf.a crc32.o \
    && ranlib /usr/lib/libelf.a \
    && ! nm -g /usr/lib/libelf.a | grep -q ' T crc32$'

RUN case "$TARGETARCH" in \
        amd64) \
            target="x86_64-unknown-linux-musl"; \
            btf_arch="x86_64"; \
            btf_sha="d00037ea649e2ac209267619c88dceecc31f5bbf4ef9f2d139dddeabc2c0f2a6"; \
            sys_include="/usr/include" ;; \
        arm64) \
            target="aarch64-unknown-linux-musl"; \
            btf_arch="arm64"; \
            btf_sha="cdd9e65811a4de0e98012dd1c59ea3a90aa57a27b6b1896d2abf83f0713d0138"; \
            sys_include="/usr/include" ;; \
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
    && printf '%s\n' "$target" > /opt/target-triple \
    && printf '%s\n' "$btf_arch" > /opt/btf-arch \
    && printf '%s\n' "$sys_include" > /opt/sys-include \
    && sha256sum "/opt/vmlinux/$btf_arch/vmlinux.h" > /opt/vmlinux.sha256 \
    && rm -f /tmp/vmlinux.btf.tar.xz /tmp/5.8.0-63-generic.btf

FROM toolchain AS audit-tool
RUN cargo install cargo-audit --version 0.22.2 --locked

FROM toolchain AS source
WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo .cargo
COPY guest guest
COPY native native
COPY scripts scripts
RUN chmod +x scripts/verify-static.sh

ENV BPF_CLANG=clang-21
ENV BPF_LLVM_READELF=llvm21-readelf
ENV LIBBPF_SYS_EXTRA_CFLAGS="-Wno-error=deprecated-declarations"

FROM source AS quality
COPY --from=audit-tool /usr/local/cargo/bin/cargo-audit /usr/local/cargo/bin/cargo-audit
RUN target="$(cat /opt/target-triple)" \
    && arch="$(cat /opt/btf-arch)" \
    && export BPF_VMLINUX_DIR="/opt/vmlinux/$arch" \
    && export BPF_SYS_INCLUDE="$(cat /opt/sys-include)" \
    && cargo fmt --all --check \
    && cargo clippy --locked --workspace --all-targets --target "$target" -- -D warnings \
    && cargo test --locked --workspace --target "$target" \
    && cargo audit --deny warnings \
    && touch /quality-ok

FROM source AS release
RUN target="$(cat /opt/target-triple)" \
    && arch="$(cat /opt/btf-arch)" \
    && export BPF_VMLINUX_DIR="/opt/vmlinux/$arch" \
    && export BPF_SYS_INCLUDE="$(cat /opt/sys-include)" \
    && cargo build --locked --release --target "$target" \
    && mkdir -p /out \
    && cp "target/$target/release/sendbox-guest-bpf" /out/ \
    && cp /opt/vmlinux.sha256 /out/ \
    && scripts/verify-static.sh \
        "/out/sendbox-guest-bpf" \
        "/out/static-link-proof.txt"

FROM scratch AS artifact
COPY --from=release /out/ /
