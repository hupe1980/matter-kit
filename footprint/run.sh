#!/usr/bin/env bash
#
# What the stack costs on a part.
#
# Links `footprint/` — a light assembled out of this crate, for an nRF52840 — and reads the
# sections out of the image. The claim this exists to check is the README's: that the crate
# scales down to a 256 KB-RAM, 1 MB-flash microcontroller. Building for
# `thumbv7em-none-eabihf` proves it compiles for the part; only a linked image says whether it
# fits on one.
#
#   ./footprint/run.sh            # print the sections and check them against the budgets
#   ./footprint/run.sh --top 20   # …and the twenty largest symbols, which is what moved
#
# The numbers are the **stack alone**: no radio. A shipping Thread light also carries
# OpenThread and a BLE host, and those are the larger half of any Matter device's flash.
# rs-matter publishes ~600–650 KB of flash and ~60 KB of `.bss` on this part *with Thread and
# BLE*, so that figure and this one are not comparable as they stand.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET=thumbv7em-none-eabihf
IMAGE="$HERE/target/$TARGET/release/matter-kit-footprint"

# Regression gates, not specification limits: a little above what it costs today, so that a
# change which adds ten kilobytes has to say so out loud. Raise them deliberately.
FLASH_BUDGET=${FLASH_BUDGET:-102400}   # 100 KiB of .text + .rodata
RAM_BUDGET=${RAM_BUDGET:-49152}        # 48 KiB of .bss

# `llvm-size` and `llvm-nm` come with the `llvm-tools` rustup component rather than with
# cargo, so they are found through the toolchain rather than on PATH.
BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin"
SIZE="$BIN/llvm-size"
NM="$BIN/llvm-nm"
if [ ! -x "$SIZE" ]; then
  echo "llvm-size not found — run: rustup component add llvm-tools" >&2
  exit 1
fi

echo "==> Linking a light for $TARGET"
# Two things this must not inherit. A cache that prunes workspace binaries but keeps cargo's
# fingerprints makes `cargo build` a no-op producing no image, so the link is forced — only this
# crate's artifacts go, its dependencies stay cached. And `RUSTFLAGS` *replaces*
# `target.<triple>.rustflags` rather than merging, so a caller that sets it (CI sets
# `-D warnings` everywhere) drops `-C link-arg=-Tlink.x`, and rust-lld then garbage-collects the
# whole program for want of `_start` and writes an image of nothing but debug sections.
(cd "$HERE" && env -u RUSTFLAGS cargo clean --release -p matter-kit-footprint --quiet 2>/dev/null || true)
(cd "$HERE" && env -u RUSTFLAGS cargo build --release --quiet)

# `llvm-size` exits 0 when it cannot read a file, printing nothing — so empty section sizes reach
# bash arithmetic as 0, and a 0 KiB image passes both budgets with `set -euo pipefail` none the
# wiser. So the image is checked first, and every section has to parse.
if [ ! -f "$IMAGE" ]; then
  echo "no image at $IMAGE — the build above did not produce one" >&2
  echo "what is there instead:" >&2
  ls -R "$HERE/target" 2>/dev/null | head -40 >&2
  exit 1
fi

section() { "$SIZE" -A "$IMAGE" | awk -v s="$1" '$1 == s { print $2 }'; }
text=$(section .text)
rodata=$(section .rodata)
bss=$(section .bss)
data=$(section .data)

# `.data` is legitimately absent on an image with no initialised statics, so it defaults rather
# than failing; the other three are not optional and an empty one means the output was not read.
data=${data:-0}
for pair in "text:$text" "rodata:$rodata" "bss:$bss"; do
  name=${pair%%:*}
  value=${pair#*:}
  case $value in
    "" | *[!0-9]*)
      echo "could not read .$name out of $IMAGE (got '$value')" >&2
      echo "$SIZE -A said:" >&2
      "$SIZE" -A "$IMAGE" >&2 || true
      exit 1
      ;;
  esac
done

flash=$((text + rodata + data))
ram=$((bss + data))

printf '\n%-28s %9s  %s\n' "section" "bytes" "what it is"
printf '%-28s %9d  %s\n' ".text" "$text" "code"
printf '%-28s %9d  %s\n' ".rodata" "$rodata" "the const data model, and every specification table"
printf '%-28s %9d  %s\n' ".data" "$data" "initialised statics"
printf '%-28s %9d  %s\n' ".bss" "$bss" "the node's tables, sized by Config, plus four buffers"
printf '\n%-28s %9d  (budget %d)\n' "flash" "$flash" "$FLASH_BUDGET"
printf '%-28s %9d  (budget %d)\n' "RAM" "$ram" "$RAM_BUDGET"

if [ "${1:-}" = "--top" ]; then
  echo
  echo "==> The ${2:-15} largest symbols"
  "$NM" --print-size --size-sort --radix=d "$IMAGE" | tail -n "${2:-15}"
fi

# What `cargo xtask stats` reads, so that the figure in the README is the figure this run
# produced rather than one somebody typed next to it. Written before the budget check, because a
# run that *failed* its budget is still the truth about this tree — and a stale number that
# happens to pass is worse than a fresh one that does not.
cat > "$(dirname "$0")/last.json" <<JSON
{
  "comment": "Written by footprint/run.sh. Not committed: it describes one machine's build.",
  "flash_bytes": $flash,
  "ram_bytes": $ram,
  "flash_kib": $((flash / 1024)),
  "ram_kib": $((ram / 1024)),
  "text_bytes": $text,
  "rodata_bytes": $rodata,
  "data_bytes": $data,
  "bss_bytes": $bss
}
JSON

status=0
if [ "$flash" -gt "$FLASH_BUDGET" ]; then
  echo "FAIL: flash $flash exceeds the budget of $FLASH_BUDGET" >&2
  status=1
fi
if [ "$ram" -gt "$RAM_BUDGET" ]; then
  echo "FAIL: RAM $ram exceeds the budget of $RAM_BUDGET" >&2
  status=1
fi
if [ "$status" -eq 0 ]; then
  echo
  echo "PASS: a light fits in $((flash / 1024)) KiB of flash and $((ram / 1024)) KiB of RAM."
fi
exit "$status"
