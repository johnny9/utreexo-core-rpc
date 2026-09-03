#!/usr/bin/env bash

set -euo pipefail

BRIDGE=${1:?usage: cli_path_validation_tests.sh /path/to/utreexo-bridge}
TEST_ROOT=$(mktemp -d)
cleanup()
{
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

expect_rejected()
{
    local name=$1
    local expected=$2
    shift 2
    local output="$TEST_ROOT/$name.log"

    set +e
    "$BRIDGE" --rpc-cookie="$TEST_ROOT/missing.cookie" "$@" >"$output" 2>&1
    local status=$?
    set -e
    [[ $status -ne 0 ]]
    grep -F 'event=path_configuration_invalid' "$output" >/dev/null
    grep -F -- "$expected" "$output" >/dev/null
    if grep -F 'event=cookie_read_failed' "$output" >/dev/null; then
        echo "$name reached cookie/RPC setup before rejecting unsafe paths" >&2
        return 1
    fi
}

expect_rejected normalized-file-alias 'must refer to different files' \
    --checkpoint="$TEST_ROOT/base.chk" \
    --recovery-checkpoint="$TEST_ROOT/missing/../base.chk"

printf 'checkpoint sentinel\n' >"$TEST_ROOT/existing.chk"
ln "$TEST_ROOT/existing.chk" "$TEST_ROOT/existing-hardlink.chk"
expect_rejected hardlink-file-alias 'must refer to different files' \
    --checkpoint="$TEST_ROOT/existing.chk" \
    --recovery-checkpoint="$TEST_ROOT/existing-hardlink.chk"
grep -F 'checkpoint sentinel' "$TEST_ROOT/existing.chk" >/dev/null

expect_rejected online-file-descendant \
    '--state-json must not be the same as or inside --online-state' \
    --online-state="$TEST_ROOT/online" \
    --state-json="$TEST_ROOT/online/state.json"
[[ ! -e "$TEST_ROOT/online" ]]

expect_rejected proof-file-descendant \
    '--recovery-checkpoint must not be the same as or inside --proof-store' \
    --recovery-checkpoint="$TEST_ROOT/proofs/proofs.dat" \
    --proof-store="$TEST_ROOT/proofs"
[[ ! -e "$TEST_ROOT/proofs" ]]

expect_rejected automatic-recovery-storage-collision \
    '--recovery-checkpoint must not be the same as or inside --online-state' \
    --checkpoint="$TEST_ROOT/published.chk" \
    --online-state="$TEST_ROOT/published.chk.resume"
[[ ! -e "$TEST_ROOT/published.chk.resume" ]]

expect_rejected nested-storage-directories \
    'must be separate, non-nested directories' \
    --online-state="$TEST_ROOT/storage" \
    --proof-store="$TEST_ROOT/storage/proofs"
[[ ! -e "$TEST_ROOT/storage" ]]

mkdir "$TEST_ROOT/storage-target"
ln -s "$TEST_ROOT/storage-target" "$TEST_ROOT/storage-link"
expect_rejected symlinked-storage-directories \
    'must be separate, non-nested directories' \
    --online-state="$TEST_ROOT/storage-target" \
    --proof-store="$TEST_ROOT/storage-link/proofs"
[[ -z $(find "$TEST_ROOT/storage-target" -mindepth 1 -print -quit) ]]

echo 'CLI path validation tests passed'
