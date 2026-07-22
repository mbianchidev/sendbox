#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <binary> <proof-output>" >&2
    exit 64
fi

binary=$1
proof=$2
program_headers=$(mktemp)
dynamic_section=$(mktemp)
trap 'rm -f "$program_headers" "$dynamic_section"' EXIT

file_output=$(file "$binary")
if ! printf '%s\n' "$file_output" | grep -Eq "ELF .*(statically linked|static-pie linked)"; then
    echo "file does not report a static ELF binary: $file_output" >&2
    exit 1
fi

readelf --program-headers "$binary" >"$program_headers"
if grep -q "INTERP" "$program_headers"; then
    echo "binary contains an unexpected dynamic interpreter" >&2
    exit 1
fi

readelf --dynamic "$binary" >"$dynamic_section" 2>&1
if grep -q "(NEEDED)" "$dynamic_section"; then
    echo "binary contains an unexpected shared dependency" >&2
    exit 1
fi

{
    printf '%s\n' "$file_output"
    printf 'readelf_interpreter=none\n'
    printf 'readelf_needed=none\n'
} >"$proof"
