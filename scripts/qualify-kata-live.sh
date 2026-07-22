#!/bin/sh
set -eu

: "${SENDBOX_KATA_LIVE:?set SENDBOX_KATA_LIVE=1}"
: "${SENDBOX_KATA_CONFIG:?set an absolute sandbox config path}"
: "${SENDBOX_KATA_IMAGE:?set a digest-pinned workload image}"
: "${SENDBOX_KATA_BUNDLE:?set an absolute signed bundle path}"
: "${SENDBOX_KATA_TRUST_ROOT:?set an absolute trust-root path}"

if [ "$SENDBOX_KATA_LIVE" != "1" ]; then
  echo "SENDBOX_KATA_LIVE must equal 1" >&2
  exit 2
fi

nerdctl_bin="${SENDBOX_NERDCTL:-nerdctl}"
namespace="${SENDBOX_KATA_NAMESPACE:-sendbox}"
output=".kata-live-output.$$"
trap 'rm -f "$output"' EXIT HUP INT TERM

test -c /dev/kvm
"$nerdctl_bin" --namespace "$namespace" info >/dev/null

set +e
./target/release/sendbox-rs run \
  --config "$SENDBOX_KATA_CONFIG" \
  --runtime kata \
  --image "$SENDBOX_KATA_IMAGE" \
  --bundle "$SENDBOX_KATA_BUNDLE" \
  --trust-root "$SENDBOX_KATA_TRUST_ROOT" \
  --trust-root-id "${SENDBOX_KATA_TRUST_ROOT_ID:-external-release-root}" \
  --minimum-release-sequence "${SENDBOX_KATA_MINIMUM_RELEASE_SEQUENCE:-1}" \
  --json \
  -- /usr/bin/printf '%s\n' sendbox-kata-live \
  >"$output"
status=$?
set -e

cat "$output"
test "$status" -eq 0
jq -s -e '
  any(.[]; .event == "output" and .stream == "stdout" and .encoding == "hex")
  and (last | .event == "result" and .ok == true and .exit_code == 0)
' "$output" >/dev/null

orphans=$(
  "$nerdctl_bin" --namespace "$namespace" ps -a \
    --filter label=dev.sendbox.managed=true \
    --format '{{.ID}}'
)
if [ -n "$orphans" ]; then
  echo "Kata qualification left managed containers: $orphans" >&2
  exit 1
fi
