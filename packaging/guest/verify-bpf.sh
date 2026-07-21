#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <bpf-object>" >&2
    exit 64
fi

object=$1
sections=$(mktemp)
trap 'rm -f "$sections"' EXIT

llvm21-readelf --sections "$object" >"$sections"
for required in ".BTF" ".BTF.ext" "tracepoint/sched" "tracepoint/raw_syscalls"; do
    if ! grep -q "$required" "$sections"; then
        echo "BPF object is missing required section $required" >&2
        exit 1
    fi
done

if ! file "$object" | grep -q "eBPF"; then
    echo "file does not identify an eBPF object" >&2
    exit 1
fi
