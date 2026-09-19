#!/usr/bin/env bash
#
# Shared plumbing for the CHIP interop scripts: build `examples/light` for Linux, put it on an
# IPv6 Docker network, and run the reference implementation's own tools against it.
#
# Sourced by `run.sh` (chip-tool commissioning) and `python.sh` (the SDK's Python test suites).
# Nothing here is specific to either; what differs between them is only what they run once the
# device is up.

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
DISCRIMINATOR=3840
DEVICE_NAME=mk-light

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$(mktemp -d)"

# `MATTER_INTEROP_KEEP=<dir>` copies the logs out before the temporary directory goes away.
# Without it a failure leaves only the tail, which is never the part that explains it.
KEEP="${MATTER_INTEROP_KEEP:-}"

mk_cleanup() {
  if [ -n "$KEEP" ]; then
    mkdir -p "$KEEP"
    cp "$OUT"/*.log "$KEEP/" 2>/dev/null || true
    docker logs "$DEVICE_NAME" >"$KEEP/device.log" 2>&1 || true
    echo "logs kept in $KEEP"
  fi
  docker rm -f "$DEVICE_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$OUT"
}

# Builds `examples/light` for Linux into $OUT/light.
#
# The source is copied rather than mounted read-only: Cargo needs a writable tree to resolve
# against `Cargo.lock`, and a read-only mount makes it re-resolve and pick versions the lock
# never saw — which surfaces as unrelated crates failing to find their own dependencies.
#
# It is copied through `tar` so that `target/` and `.git` are excluded on the way in: a
# developer's tree carries gigabytes of build artefacts the container throws away immediately.
# The registry and the target directory are named volumes, so the second run of the day
# compiles one crate instead of forty.
mk_build() {
  echo "==> Building examples/light for linux"
  docker volume create matter-kit-interop-cargo >/dev/null
  docker volume create matter-kit-interop-target >/dev/null
  docker run --rm \
    -v "$ROOT":/host:ro -v "$OUT":/out \
    -v matter-kit-interop-cargo:/usr/local/cargo/registry \
    -v matter-kit-interop-target:/target \
    rust:1-slim-bookworm bash -c '
      set -e
      mkdir -p /src
      tar -C /host --exclude=./target --exclude=./interop/target --exclude=./.git -cf - . \
        | tar -C /src -xf -
      cd /src
      CARGO_TARGET_DIR=/target cargo build --release --example light --features std
      cp /target/release/examples/light /out/light
    ' >/dev/null
}

# Starts the device on a fresh IPv6 network.
#
# `MATTER_PAA_OUT` makes the device write the root of the attestation chain it generated, so
# the commissioner has a trust anchor for it (§6.2.2.3). Without one, attestation can only be
# bypassed, and bypassing it means the DAC, the CD and the NOCSR signature are never checked.
#
# `MATTER_IFINDEX` has to be resolved inside the container: `ff02::fb` is link-local, so the
# responder joins the group and answers on one interface, and the default of 1 is loopback — on
# which no other container can hear it. Docker's index for `eth0` is not stable across runs, so
# it is read at start-up. Without this, commissionable discovery still works when the address is
# handed over directly, and *operational* discovery silently never resolves.
mk_start() {
  echo "==> Starting the device"
  mkdir -p "$OUT/paa"
  docker network create --ipv6 --subnet "$SUBNET" "$NET" >/dev/null
  mk_restart_device
}

# Replaces the device with a factory-fresh one on the same network.
#
# Every `TC_*.py` case commissions the device itself, and the SDK's own CI runs each with
# `factory-reset: true` for the reason this made obvious: a device that has already been
# commissioned has closed its commissioning window, so the *second* case in a run cannot get in
# and sits in discovery until it times out. Reusing one device across cases tests the first case
# and then measures a timeout.
mk_restart_device() {
  docker rm -f "$DEVICE_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$DEVICE_NAME" --network "$NET" \
    -v "$OUT":/app:ro -v "$OUT/paa":/paa -e MATTER_PAA_OUT=/paa \
    -e MATTER_ADVERTISE_ADDR="$DEVICE_IP" \
    debian:bookworm-slim \
    sh -c 'MATTER_IFINDEX=$(cat /sys/class/net/eth0/ifindex) exec /app/light' >/dev/null
  sleep 3

  if [ ! -s "$OUT/paa/matter-kit-dev-paa.der" ]; then
    echo "FAIL: the device wrote no PAA"
    docker logs "$DEVICE_NAME" 2>&1 | tail -20
    return 1
  fi
}

# Runs a shell command in the CHIP container, on the device's network, with mDNS up.
#
# `chip-tool` and the Python runner both initialise DNS-SD at start-up — even when they are
# handed an address — so Avahi and its D-Bus socket have to exist or they abort before sending
# anything.
mk_chip() {
  docker run --rm --network "$NET" -v "$OUT/paa":/paa:ro "$IMAGE" bash -c "
    mkdir -p /run/dbus
    dbus-daemon --system --fork 2>/dev/null
    avahi-daemon --daemonize --no-drop-root 2>/dev/null
    sleep 1
    $1
  " 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
}
