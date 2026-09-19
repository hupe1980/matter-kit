#!/usr/bin/env bash
#
# Commission `examples/light` with the CHIP SDK's own `chip-tool`.
#
# This is the one test in the repository that meets the *reference* implementation. Everything
# under `tests/` is matter-kit checking its own reading of the specification; `interop/tests/`
# checks it against rs-matter's reading; this checks it against the implementation every
# certified Matter product on the market is built from.
#
# It needs no hardware. Both ends run in containers on an IPv6 Docker network, and
# `pairing already-discovered` is given the device's address directly, so commissionable
# discovery never has to cross a container boundary. *Operational* discovery does, which is
# what `MATTER_IFINDEX` below is for.
#
#   ./interop/chip/run.sh
#
# What it asserts is the whole of Core §5.5, from PBKDFParamRequest to CommissioningComplete,
# with device attestation **verified rather than bypassed**: `examples/light` generates a
# §6.2.2 chain at start-up and writes its PAA out, and `chip-tool` is pointed at that PAA as
# its trust anchor. The tail of it is the part that is easy to skip and expensive to get wrong
# — CASE over an operational session, found by mDNS, answering the interaction model on the
# fabric that was just created.
#
# Exit status is the test result.
set -euo pipefail

# The reference implementation, pinned by digest rather than by `:latest`.
#
# `:latest` moved underneath this harness once already — a pull on 2026-09-19 carried 618
# certification cases where 603 had been recorded — and a gate that can change between two runs
# of the same commit cannot tell a regression from an upstream edit. Moving the pin is a commit
# with its own diff and its own green run, exactly like `interop/`'s `=0.3.0` pin on rs-matter.
#
# This digest is the multi-arch manifest list, so it resolves on arm64 and amd64 alike. To see
# what upstream has become without changing the gate:
#
#   CHIP_IMAGE=ghcr.io/matter-js/chip:latest ./interop/chip/run.sh
IMAGE="${CHIP_IMAGE:-ghcr.io/matter-js/chip@sha256:c69662de209a062b344c97cc8622a6147271c96f8887e747b905fab4ffb381de}"
NET="${MATTER_NET:-matter-kit-interop}"
SUBNET="fd00:1234:5678::/64"
DEVICE_IP="fd00:1234:5678::2"
PASSCODE=20202021
NODE_ID=1
# The whole of §5.5 by default, `CommissioningComplete` included — which is sent over an
# operational session, so the default run exercises CASE, operational discovery and the
# interaction model on the new fabric as well as the credentials phase.
# `SKIP_COMMISSIONING_COMPLETE=true` stops after `AddNOC`, which is useful only for bisecting
# a failure down to the PASE half.
SKIP_COMPLETE="${SKIP_COMMISSIONING_COMPLETE:-false}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$(mktemp -d)"

# `MATTER_INTEROP_KEEP=<dir>` copies the chip-tool log and the device log out before the
# temporary directory goes away. Without it a failure leaves only the last forty lines, which
# is never the part that explains it.
KEEP="${MATTER_INTEROP_KEEP:-}"
cleanup() {
  if [ -n "$KEEP" ]; then
    mkdir -p "$KEEP"
    cp "$OUT/chip-tool.log" "$KEEP/" 2>/dev/null || true
    docker logs mk-light >"$KEEP/device.log" 2>&1 || true
    echo "logs kept in $KEEP"
  fi
  docker rm -f mk-light >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$OUT"
}
trap cleanup EXIT
mkdir -p "$OUT/paa"

echo "==> Building examples/light for linux"
# The source is copied rather than mounted read-only: Cargo needs a writable tree to resolve
# against `Cargo.lock`, and a read-only mount makes it re-resolve and pick versions the lock
# never saw — which surfaces as unrelated crates failing to find their own dependencies.
#
# It is copied through `tar` rather than `cp -r` so that `target/` and `.git` are excluded on
# the way in. A developer's tree carries gigabytes of build artefacts the container throws
# away immediately; copying them first wastes minutes and can fill Docker's disk.
docker run --rm -v "$ROOT":/host:ro -v "$OUT":/out rust:1-slim-bookworm bash -c '
  set -e
  mkdir -p /src
  tar -C /host --exclude=./target --exclude=./interop/target --exclude=./.git -cf - . \
    | tar -C /src -xf -
  cd /src
  cargo build --release --example light --features std
  cp target/release/examples/light /out/light
' >/dev/null

echo "==> Starting the device"
docker network create --ipv6 --subnet "$SUBNET" "$NET" >/dev/null
# `MATTER_PAA_OUT` makes the device write the root of the attestation chain it generated, so
# that the commissioner has a trust anchor for it (§6.2.2.3). Without one, attestation can only
# be bypassed, and bypassing it means the DAC, the CD and the NOCSR signature are never checked.
#
# `MATTER_IFINDEX` has to be resolved inside the container: `ff02::fb` is link-local, so the
# responder joins the group and sends its answers on one interface, and the default of 1 is
# loopback — on which no other container can hear it. Docker's index for `eth0` is not stable
# across runs, so it is read at start-up rather than hard-coded. Without this, PASE still
# succeeds (`already-discovered` is given an address) and *operational* discovery silently
# never resolves, which looks like a CASE failure and is not one.
docker run -d --name mk-light --network "$NET" \
  -v "$OUT":/app:ro -v "$OUT/paa":/paa -e MATTER_PAA_OUT=/paa \
  -e MATTER_ADVERTISE_ADDR="$DEVICE_IP" \
  debian:bookworm-slim \
  sh -c 'MATTER_IFINDEX=$(cat /sys/class/net/eth0/ifindex) exec /app/light' >/dev/null
sleep 3

if [ ! -s "$OUT/paa/matter-kit-dev-paa.der" ]; then
  echo "FAIL: the device wrote no PAA"; docker logs mk-light 2>&1 | tail -20; exit 1
fi

echo "==> chip-tool: commissioning"
# `chip-tool` initialises DNS-SD at startup even for `already-discovered`, so Avahi and its
# D-Bus socket have to exist or it aborts before sending anything.
LOG="$OUT/chip-tool.log"
docker run --rm --network "$NET" -v "$OUT/paa":/paa:ro "$IMAGE" bash -c "
  mkdir -p /run/dbus /tmp/ct
  dbus-daemon --system --fork 2>/dev/null
  avahi-daemon --daemonize --no-drop-root 2>/dev/null
  sleep 1
  chip-tool pairing already-discovered $NODE_ID $PASSCODE $DEVICE_IP 5540 \
    --paa-trust-store-path /paa \
    --skip-commissioning-complete $SKIP_COMPLETE \
    --storage-directory /tmp/ct 2>&1
" | sed 's/\x1b\[[0-9;]*m//g' > "$LOG" || true

echo
grep -E "Starting commissioning stage|Error on|Device commissioning|err [0-9]" "$LOG" || true
echo
echo "==> Device log"
docker logs mk-light 2>&1 | tail -3

if grep -q "Device commissioning completed with success" "$LOG"; then
  echo
  if [ "$SKIP_COMPLETE" = "false" ]; then
    echo "PASS: chip-tool commissioned matter-kit end to end — PASE, attestation verified,"
    echo "      CSR, AddNOC, operational discovery, CASE, CommissioningComplete."
  else
    echo "PASS: chip-tool commissioned matter-kit — PASE, attestation verified, CSR, AddNOC."
  fi
  exit 0
fi

echo
echo "FAIL: commissioning did not complete. Tail of the log:"
tail -40 "$LOG"
exit 1
