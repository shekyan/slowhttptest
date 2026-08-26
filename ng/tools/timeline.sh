#!/bin/sh
# Repeat a run and print where each one's wall time actually went.
#
# Runs against a real target vary from 20 s to 959 s for identical invocations,
# and the cost has moved between phases as each was instrumented, so a single
# run tells you nothing. Each line shows the tool's own phase timeline next to
# the shell's total; the difference between "in process" and "total" is time
# after _exit(), which is the kernel tearing the process down.
#
#   usage: tools/timeline.sh <url> [connections] [runs]

set -e
URL=${1:?usage: timeline.sh <url> [connections] [runs]}
CONNS=${2:-1500}
RUNS=${3:-5}
BIN=$(dirname "$0")/../build/slowhttptest-ng

# Wait for the machine to return to rest before each run.
#
# Starting the next run the instant the previous process exits does not measure
# the tool, it measures whatever the previous run left behind: 1500 sockets are
# still draining, and on macOS they are still attached to the content filter
# while it works through them. Back-to-back runs produced a giveaway alternating
# pattern -- a slow run, then a fast one, then slow again -- because a run that
# spends 50s tearing down leaves the machine clean for its successor, while a
# run that exits in 20s dumps its sockets on the one after it.
#
# So this waits for net.cfil.sock_attached_count to come back down near where it
# started rather than sleeping a fixed guess. Falls back to a plain sleep where
# that sysctl does not exist.
attached() { sysctl -n net.cfil.sock_attached_count 2>/dev/null || echo ""; }

BASE=$(attached)
settle() {
  [ -n "$BASE" ] || { sleep 30; return 0; }
  waited=0
  while [ "$waited" -lt 180 ]; do
    now=$(attached)
    case "$now" in
      ''|*[!0-9]*) break ;;
    esac
    # Within 10% of baseline is "at rest"; the count drifts with normal desktop
    # traffic and will not return to the exact number.
    if [ "$now" -le $(( BASE + BASE / 10 + 20 )) ]; then
      # Note the explicit if. "test && printf" as the last statement makes this
      # function return 1 whenever the wait was zero, and under set -e that takes
      # the whole script down without printing a single result.
      if [ "$waited" -gt 0 ]; then
        printf '        (settled after %ss)\n' "$waited"
      fi
      return 0
    fi
    sleep 5
    waited=$(( waited + 5 ))
  done
  printf '        (gave up waiting to settle after %ss, still %s attached)\n' \
    "$waited" "$(attached)"
  return 0
}

[ -n "$BASE" ] && printf 'baseline net.cfil.sock_attached_count: %s\n\n' "$BASE"

i=1
while [ "$i" -le "$RUNS" ]; do
  settle
  start=$(date +%s)
  out=$("$BIN" -X -u "$URL" -c "$CONNS" -r 500 -l 20 --no-probe 2>&1) || true
  total=$(( $(date +%s) - start ))
  addr=$(printf '%s\n' "$out" | sed -n 's/.*resolved [^ ]* to \([^ ]*\).*/\1/p')
  line=$(printf '%s\n' "$out" | sed -n 's/^  timeline: \(.*\)/\1/p')
  [ -n "$line" ] || line="NO TIMELINE -- $(printf '%s\n' "$out" |
    grep -E '^ERROR|^Done' | head -1)"
  printf 'run %d  shell total %4ds  %-34s %s\n' "$i" "$total" "$addr" "$line"
  i=$((i + 1))
done
