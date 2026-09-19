#!/usr/bin/env bash
#
# Run the CSA Test Harness's own Python test cases against `examples/light`.
#
#   ./interop/chip/python.sh TC_CGEN_2_1 TC_OPCREDS_3_1
#   ./interop/chip/python.sh --list
#
# These are the *certification* suites — the same `TC_*.py` scripts the Test Harness executes
# at an authorised test lab, shipped inside the CHIP image with the `matter` Python package
# they import. Everything under `tests/` in this repository is matter-kit checking its own
# reading of the specification; this is the specification's own checker, written by somebody
# else, executing against this crate.
#
# Each script commissions the device itself over `on-network` discovery, which means every run
# exercises the whole of §5.5 before the first assertion of the test case — mDNS, PASE,
# attestation against the PAA the device wrote, CASE, and the interaction model on the new
# fabric.
#
# Exit status is the test result: zero only if every named suite passed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

if [ "${1:-}" = "--list" ]; then
  docker run --rm --entrypoint sh "$IMAGE" -c 'ls /src/python_testing/TC_*.py | xargs -n1 basename | sed "s/\.py$//"'
  exit 0
fi

if [ $# -eq 0 ]; then
  echo "usage: $0 TC_NAME [TC_NAME ...]    ($0 --list to enumerate)" >&2
  exit 2
fi

trap mk_cleanup EXIT

# The arguments a case needs come from the case, not from a guess here.
#
# Every `TC_*.py` declares, in a `=== BEGIN CI TEST ARGUMENTS ===` header, the `script-args` the
# SDK's own CI passes it. Most of that is what this script already supplies, but a large
# minority add a `--endpoint` or a PIXIT — and without it such a case does not fail an
# assertion, it declines to run ("The --endpoint flag is required for this test"), which Mobly
# reports as a failed test.
#
# Flags this script sets itself are dropped, and so is any value still holding an unexpanded
# `${...}` — those name companion binaries and trace sinks that exist only in the SDK's CI.
# Only the first run block is read; later ones may name a different endpoint, and two
# `--endpoint` flags is not a case.
mk_case_args() {
  docker run --rm -i --entrypoint python3 "$IMAGE" - "$@" <<'PY'
# Reads the `=== BEGIN CI TEST ARGUMENTS ===` block a `TC_*.py` carries and prints the
# `script-args` of its first run, minus everything `python.sh` supplies itself.
import re
import sys

# Set by the runner, or naming something that exists only in the SDK's own CI.
OURS = {
    "--storage-path",
    "--commissioning-method",
    "--discriminator",
    "--passcode",
    "--paa-trust-store-path",
    "--PICS",
    "--trace-to",
    "--manual-code",
    "--qr-code",
    # Drives the *reference* application through a named pipe. There is no such pipe here, and
    # a case that needs one to reach its assertions cannot be run against this device anyway.
    "--app-pipe",
    # Relaxes the case to accept a known specification erratum. Its own name says it is not
    # admissible for certification, and TC_IDM_2_2 passes here without it: taking it from the
    # header would quietly lower the bar this runner measures against.
    "--enable-spec-errata-ci-only-disallowed-for-certification",
}

for name in sys.argv[1:]:
    try:
        with open(f"/src/python_testing/{name}.py", encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        print(f"{name}\t")
        continue

    block = re.search(
        r"BEGIN CI TEST ARGUMENTS ===(.*?)END CI TEST ARGUMENTS", text, re.S
    )
    args = []
    if block:
        lines = [re.sub(r"^#\s?", "", line) for line in block.group(1).splitlines()]
        for index, line in enumerate(lines):
            if "script-args:" not in line:
                continue
            indent = len(line) - len(line.lstrip())
            for rest in lines[index + 1 :]:
                if not rest.strip():
                    continue
                if len(rest) - len(rest.lstrip()) <= indent:
                    break
                args.extend(rest.split())
            break  # The first run only: later runs may name a different endpoint.

    kept = []
    flag = None
    values = []

    def flush():
        if flag and flag not in OURS and not any("${" in v for v in values):
            kept.append(flag)
            kept.extend(values)

    for token in args:
        if token.startswith("--"):
            flush()
            flag, values = token, []
        elif flag:
            values.append(token)
    flush()
    print(f"{name}\t{' '.join(kept)}")
PY
}

mk_build
mk_start

ARGS_FILE="$OUT/case-args.tsv"
mk_case_args "$@" >"$ARGS_FILE"

passed=0
failed=0
skipped_cases=0
failures=()
skips=()

# Each case gets a factory-fresh device, and a bound on how long it may take.
TIMEOUT_S="${MATTER_TC_TIMEOUT:-300}"

first=1
for tc in "$@"; do
  echo
  echo "==> $tc"
  # The first case uses the device `mk_start` already brought up; every later one gets a new
  # one, because a commissioned device has closed its commissioning window and the next case
  # would sit in discovery until it timed out.
  if [ $first -eq 0 ]; then
    mk_restart_device || { echo "    FAIL (device would not start)"; failed=$((failed + 1)); continue; }
  fi
  first=0
  log="$OUT/$tc.log"
  extra="$(awk -F'\t' -v n="$tc" '$1 == n { print $2 }' "$ARGS_FILE")"
  [ -n "$extra" ] && echo "    | args: $extra" || true
  # `--commissioning-method on-network` makes the runner discover and commission the device
  # itself rather than reusing somebody else's fabric, so each case starts from a factory-fresh
  # relationship. `--storage-path` is per case for the same reason.
  #
  # `--paa-trust-store-path` points at the root the device generated, so device attestation is
  # verified rather than bypassed — the same anchor `run.sh` gives chip-tool.
  mk_chip "cd /src/python_testing && timeout $TIMEOUT_S python3 $tc.py \
      --storage-path /tmp/$tc.json \
      --commissioning-method on-network \
      --discriminator $DISCRIMINATOR \
      --passcode $PASSCODE \
      --paa-trust-store-path /paa \
      --PICS /src/app/tests/suites/certification/ci-pics-values \
      $extra" > "$log" || true

  # Mobly's own summary line is the verdict, and it is the only thing in the log that is one:
  # `Test results: Error 0, Executed 2, Failed 0, Passed 2, Requested 2, Skipped 0`. A passing
  # case prints no "Final result: PASS" — only a failing one prints "Final result: FAIL !" — so
  # matching on that reports every pass as a failure.
  #
  # Read it **whole**. `Passed` must equal `Requested` and `Skipped` must be zero:
  # `Executed 1, Failed 0, Passed 1, Requested 2, Skipped 1` is the commissioning that precedes
  # every case, and then the case itself declining to run. Most `TC_*.py` are gated on a
  # `has_attribute`/`has_feature` decorator, so a device missing the thing under test does not
  # fail the case — it skips it, silently, and a runner stopping at `Failed 0` calls that a
  # pass.
  verdict="$(grep -oE "^Test results: Error [0-9]+, Executed [0-9]+, Failed [0-9]+, Passed [0-9]+, Requested [0-9]+, Skipped [0-9]+" "$log" | tail -1)"
  numbers="$(echo "$verdict" | grep -oE "[0-9]+" | tr "\n" " ")"
  read -r errors _executed failed_tests passes requested skipped <<EOF2
$numbers
EOF2
  if [ -n "$verdict" ] \
     && [ "${errors:-1}" -eq 0 ] && [ "${failed_tests:-1}" -eq 0 ] && [ "${skipped:-1}" -eq 0 ] \
     && [ "${passes:-0}" -gt 0 ] && [ "${passes:-0}" -eq "${requested:--1}" ] \
     && ! grep -q "Final result: FAIL" "$log"; then
    echo "    PASS"
    passed=$((passed + 1))
  else
    # A skip is not a failure of the device and saying "FAIL" for one sends the next hour in
    # the wrong direction. It is still not a pass.
    if [ -n "$verdict" ] && [ "${skipped:-0}" -gt 0 ] && [ "${failed_tests:-0}" -eq 0 ] \
       && [ "${errors:-0}" -eq 0 ]; then
      echo "    SKIP  ($verdict)"
      echo "    | the case declined to run — usually a \`has_attribute\`/\`has_feature\`"
      echo "    | decorator the device does not satisfy. Not a pass."
      skipped_cases=$((skipped_cases + 1))
      skips+=("$tc")
      continue
    fi
    echo "    FAIL"
    failed=$((failed + 1))
    failures+=("$tc")
    # The *failure*, not the tail: a Mobly run ends with a configuration dump, so `tail` prints
    # the one part of the log that says nothing about why the case failed. Mobly also
    # distinguishes a *Failure* (an assertion) from an *Error* (an exception), and only the
    # first carries `Details=` — so match both, or an exception comes back as a bare `FAIL`.
    #
    # The last step reached is worth as much as the error: it is the difference between
    # "stopped at step 15" and "stopped at step 37".
    if grep -qE "Details=|TestFailure|Traceback|ERROR" "$log"; then
      { grep -hE "\*\*\*\*\* Test Step" "$log" || true; } | tail -1 | sed 's/.*INFO //; s/^/    | last: /'
      # `-A1` because Mobly puts the reason on the line *after* `Details=`; matching the marker
      # alone prints a bare `Details=` and nothing else.
      { grep -hA1 -E "Details=|TestFailure:|AssertionError|^[A-Za-z.]*Error(:| )|ERROR .*(failed|Exception)" "$log" || true; } \
        | sed 's/^.*ERROR /ERROR /; s/^ *//' | grep -vE '^(--|, Extras=None)$' | sed '/^$/d' | sort -u | head -8 | sed 's/^/    | /' || true
    else
      tail -25 "$log" | sed 's/^/    | /'
    fi
    if [ -n "$KEEP" ]; then
      echo "    | (full log: \$MATTER_INTEROP_KEEP/$tc.log)"
    else
      echo "    | (set MATTER_INTEROP_KEEP=<dir> to keep the full log and the device's)"
    fi
  fi
done

echo
echo "==> $passed passed, $failed failed, $skipped_cases skipped"
if [ $skipped_cases -ne 0 ]; then
  echo "    skipped: ${skips[*]}"
fi
if [ $failed -ne 0 ]; then
  echo "    failing: ${failures[*]}"
fi
# A skip exits non-zero too: it is a case that was asked for and did not run, which is not a
# pass and must not be counted as one.
if [ $failed -ne 0 ] || [ $skipped_cases -ne 0 ]; then
  exit 1
fi
