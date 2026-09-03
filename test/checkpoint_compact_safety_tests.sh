#!/usr/bin/env bash

set -euo pipefail

COMPACTOR=${1:?usage: checkpoint_compact_safety_tests.sh /path/to/utreexo-checkpoint-compact}
if ! command -v python3 >/dev/null 2>&1; then
    echo "Skipping checkpoint compactor safety tests: python3 is unavailable"
    exit 77
fi

TEST_ROOT=$(mktemp -d)
cleanup()
{
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

make_checkpoint()
{
    local path=$1
    local slots=$2
    python3 - "$path" "$slots" <<'PY'
import struct
import sys

path = sys.argv[1]
slots = int(sys.argv[2])
no_node = 0xffffffff
prefix = (
    b"UTRCHKPT"
    + struct.pack("<II", 3, 0)
    + bytes(32)
    + struct.pack("<Q", 1)
    + bytes(32)
    + b"UTRFORST"
    + struct.pack("<IQQ", 1, slots, slots)
    + struct.pack("<64I", *([no_node] * 64))
)
record = b"\x01" + bytes(32) + struct.pack("<III", no_node, no_node, no_node)
payload = prefix + record * slots
checksum = 14695981039346656037
for byte in payload:
    checksum ^= byte
    checksum = (checksum * 1099511628211) & 0xffffffffffffffff
with open(path, "wb") as output:
    output.write(payload)
    output.write(struct.pack("<Q", checksum))
PY
}

expect_failure()
{
    local log=$1
    shift
    set +e
    "$COMPACTOR" "$@" >"$log" 2>&1
    local status=$?
    set -e
    [[ $status -ne 0 ]]
}

SOURCE=$TEST_ROOT/source.chk
make_checkpoint "$SOURCE" 8
printf 'external compactor sentinel\n' >"$TEST_ROOT/sentinel"

SYMLINK_OUTPUT=$TEST_ROOT/symlink-output.chk
ln -s "$TEST_ROOT/sentinel" "$SYMLINK_OUTPUT.tmp"
expect_failure "$TEST_ROOT/symlink.log" "$SOURCE" "$SYMLINK_OUTPUT"
grep -F 'symbolic link' "$TEST_ROOT/symlink.log" >/dev/null
grep -Fx 'external compactor sentinel' "$TEST_ROOT/sentinel" >/dev/null

HARDLINK_OUTPUT=$TEST_ROOT/hardlink-output.chk
ln "$TEST_ROOT/sentinel" "$HARDLINK_OUTPUT.tmp"
expect_failure "$TEST_ROOT/hardlink.log" "$SOURCE" "$HARDLINK_OUTPUT"
grep -F 'hard-linked' "$TEST_ROOT/hardlink.log" >/dev/null
grep -Fx 'external compactor sentinel' "$TEST_ROOT/sentinel" >/dev/null

MAP_OUTPUT=$TEST_ROOT/map-output.chk
ln "$TEST_ROOT/sentinel" "$MAP_OUTPUT.node-map.tmp"
expect_failure "$TEST_ROOT/map.log" "$SOURCE" "$MAP_OUTPUT"
grep -F 'hard-linked' "$TEST_ROOT/map.log" >/dev/null
grep -Fx 'external compactor sentinel' "$TEST_ROOT/sentinel" >/dev/null

# INPUT can lexically be OUTPUT.tmp. It must be rejected before stale-temp
# recovery has any opportunity to unlink or truncate the checkpoint.
ALIAS_OUTPUT=$TEST_ROOT/source
cp "$SOURCE" "$ALIAS_OUTPUT.tmp"
ALIAS_SIZE=$(wc -c <"$ALIAS_OUTPUT.tmp")
expect_failure "$TEST_ROOT/input-alias.log" "$ALIAS_OUTPUT.tmp" "$ALIAS_OUTPUT"
grep -F 'INPUT must not alias' "$TEST_ROOT/input-alias.log" >/dev/null
[[ $(wc -c <"$ALIAS_OUTPUT.tmp") == "$ALIAS_SIZE" ]]

SYMLINK_ALIAS_OUTPUT=$TEST_ROOT/source-via-symlink
cp "$SOURCE" "$SYMLINK_ALIAS_OUTPUT.tmp"
ln -s "$SYMLINK_ALIAS_OUTPUT.tmp" "$TEST_ROOT/source-link.chk"
SYMLINK_ALIAS_SIZE=$(wc -c <"$SYMLINK_ALIAS_OUTPUT.tmp")
expect_failure "$TEST_ROOT/input-symlink-alias.log" \
    "$TEST_ROOT/source-link.chk" "$SYMLINK_ALIAS_OUTPUT"
grep -F 'INPUT must not alias' "$TEST_ROOT/input-symlink-alias.log" >/dev/null
[[ $(wc -c <"$SYMLINK_ALIAS_OUTPUT.tmp") == "$SYMLINK_ALIAS_SIZE" ]]

# A normal abandoned map/output pair is recoverable when no compactor holds the
# map lock.
STALE_OUTPUT=$TEST_ROOT/stale-output.chk
printf 'stale map\n' >"$STALE_OUTPUT.node-map.tmp"
printf 'stale output\n' >"$STALE_OUTPUT.tmp"
"$COMPACTOR" "$SOURCE" "$STALE_OUTPUT" >"$TEST_ROOT/stale.log" 2>&1
grep -F 'event=checkpoint_compacted' "$TEST_ROOT/stale.log" >/dev/null
[[ -f "$STALE_OUTPUT" ]]
[[ ! -e "$STALE_OUTPUT.tmp" ]]
[[ ! -e "$STALE_OUTPUT.node-map.tmp" ]]

# Observe the map entry to prove the initial OUTPUT check has completed, then
# create OUTPUT while the first pass is still scanning a larger checkpoint.
RACE_SOURCE=$TEST_ROOT/race-source.chk
RACE_OUTPUT=$TEST_ROOT/race-output.chk
make_checkpoint "$RACE_SOURCE" 250000
"$COMPACTOR" "$RACE_SOURCE" "$RACE_OUTPUT" >"$TEST_ROOT/race.log" 2>&1 &
COMPACTOR_PID=$!
while [[ ! -e "$RACE_OUTPUT.node-map.tmp" ]]; do
    if ! kill -0 "$COMPACTOR_PID" 2>/dev/null; then
        wait "$COMPACTOR_PID" || true
        echo "compactor exited before the publication-race sentinel was installed" >&2
        exit 1
    fi
done
printf 'late output sentinel\n' >"$RACE_OUTPUT"
set +e
wait "$COMPACTOR_PID"
RACE_STATUS=$?
set -e
[[ $RACE_STATUS -ne 0 ]]
grep -F 'without replacing OUTPUT' "$TEST_ROOT/race.log" >/dev/null
grep -Fx 'late output sentinel' "$RACE_OUTPUT" >/dev/null

echo "checkpoint compactor safety tests passed"
