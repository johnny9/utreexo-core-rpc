#!/usr/bin/env bash

set -euo pipefail

role=$(basename -- "$0")
case $role in
    fake-sidecar*)
        if [[ ${1:-} == --version ]]; then
            echo "utreexo-bridge pipeline-test-$role checkpoint_format=3 forest_format=1"
            exit 0
        fi
        checkpoint=
        state=
        height=
        for argument in "$@"; do
            case $argument in
                --checkpoint=*) checkpoint=${argument#*=} ;;
                --state-json=*) state=${argument#*=} ;;
                --stop-height=*) height=${argument#*=} ;;
            esac
        done
        if [[ $role == fake-sidecar && $height == 500000 && ! -e ${FAKE_RETRY_MARKER:?} ]]; then
            touch "$FAKE_RETRY_MARKER"
            echo 'timestamp=2026-08-31T00:00:00Z level=warn event=rpc_call_failed error="forced"'
            exit 1
        fi
        if [[ $role == fake-sidecar-old ]]; then sleep 3; else sleep 1; fi
        printf '%s\n' "$height" > "$checkpoint"
        printf '{"format":1,"height":%s,"block_hash":"hash-%s","num_leaves":%s,"roots":["root-%s"]}\n' \
            "$height" "$height" "$height" "$height" > "$state"
        echo "timestamp=2026-08-31T00:00:00Z level=info event=checkpoint_saved height=$height"
        exit 0
        ;;
    fake-compactor)
        cp -- "$1" "$2"
        echo 'event=checkpoint_compacted roots=verified'
        exit 0
        ;;
    fake-bitcoin-cli)
        case ${2:-} in
            getblockchaininfo)
                echo '{"chain":"main","initialblockdownload":false,"pruned":false,"blocks":1000000,"headers":1000000}'
                ;;
            getblockhash) echo 'old-block-hash' ;;
            getblock) echo '{"tx":[{}, {"vin":[{"prevout":{}}]}]}' ;;
            *) exit 1 ;;
        esac
        exit 0
        ;;
esac

for command in tmux jq sha256sum stdbuf flock rg tee; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Skipping pipeline integration test: missing $command"
        exit 77
    fi
done

TEST_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SIDECAR_DIR=$(cd -- "$TEST_DIR/.." && pwd)
TEST_ROOT=$(mktemp -d)
HANDOFF_CONTROLLER_SESSION=utreexo-handoff-controller-$$
HANDOFF_WATCH_SESSION=utreexo-handoff-watch-$$
cleanup()
{
    local exit_status=$?
    if (( exit_status != 0 )) && [[ -d "$TEST_ROOT" ]]; then
        echo "handoff test failed; retained log tails follow" >&2
        for log in "$TEST_ROOT"/handoff/*.log; do
            [[ -f "$log" ]] || continue
            echo "--- $log" >&2
            tail -n 40 "$log" >&2
        done
    fi
    tmux kill-session -t "$HANDOFF_CONTROLLER_SESSION" 2>/dev/null || true
    tmux kill-session -t "$HANDOFF_WATCH_SESSION" 2>/dev/null || true
    rm -rf -- "$TEST_ROOT"
    return "$exit_status"
}
trap cleanup EXIT
BIN_DIR=$TEST_ROOT/bin
SUCCESS_DIR=$TEST_ROOT/success
MISMATCH_DIR=$TEST_ROOT/mismatch
HANDOFF_DIR=$TEST_ROOT/handoff
mkdir -p -- "$BIN_DIR" "$SUCCESS_DIR" "$MISMATCH_DIR" "$HANDOFF_DIR"
ln -s -- "$TEST_DIR/mainnet_rebuild_validate_tests.sh" "$BIN_DIR/fake-sidecar"
ln -s -- "$TEST_DIR/mainnet_rebuild_validate_tests.sh" "$BIN_DIR/fake-compactor"
ln -s -- "$TEST_DIR/mainnet_rebuild_validate_tests.sh" "$BIN_DIR/fake-bitcoin-cli"
cp -- "$TEST_DIR/mainnet_rebuild_validate_tests.sh" "$BIN_DIR/fake-sidecar-old"
cp -- "$TEST_DIR/mainnet_rebuild_validate_tests.sh" "$BIN_DIR/fake-sidecar-new"
printf '\n# Distinct handoff test binary.\n' >> "$BIN_DIR/fake-sidecar-new"
chmod 755 "$BIN_DIR/fake-sidecar-old" "$BIN_DIR/fake-sidecar-new"
printf 'user:password\n' > "$TEST_ROOT/cookie"
printf '%s\n' \
    '{"format":1,"height":900001,"block_hash":"hash-900001","num_leaves":900001,"roots":["root-900001"]}' \
    > "$TEST_ROOT/reference.json"

run_controller()
{
    local run_dir=$1
    local reference=$2
    UTREEXO_BINARY="$BIN_DIR/fake-sidecar" \
    UTREEXO_COMPACTOR="$BIN_DIR/fake-compactor" \
    UTREEXO_BITCOIN_CLI="$BIN_DIR/fake-bitcoin-cli" \
    UTREEXO_RPC_COOKIE="$TEST_ROOT/cookie" \
    UTREEXO_REBUILD_RUN_DIR="$run_dir" \
    UTREEXO_REBUILD_REFERENCE_STATE="$reference" \
    UTREEXO_REBUILD_MAX_ATTEMPTS=2 \
    UTREEXO_REBUILD_RETRY_DELAY_SECONDS=0 \
    UTREEXO_REBUILD_MIN_FREE_GIB=1 \
    UTREEXO_REBUILD_LOG_LEVEL=info \
    UTREEXO_CHECKPOINT_SHA256=1 \
    FAKE_RETRY_MARKER="$TEST_ROOT/retry-marker" \
        "$SIDECAR_DIR/tools/mainnet-rebuild-validate.sh" internal-run 900001
}

run_controller "$SUCCESS_DIR" "$TEST_ROOT/reference.json" > "$TEST_ROOT/success.log" 2>&1
jq -e '.state == "complete" and .stage == "validation"' \
    "$SUCCESS_DIR/pipeline-status.json" >/dev/null
jq -e '.status == "validated" and
       .compact_checkpoint.reload_state_verified == true and
       .final_state.reference_validation == "match"' \
    "$SUCCESS_DIR/rebuild-validation-manifest.json" >/dev/null
[[ $(< "$SUCCESS_DIR/mainnet-900000-compact-v3.chk") == 900000 ]]
[[ $(< "$SUCCESS_DIR/mainnet-final-active-v3.chk") == 900001 ]]
[[ -s "$SUCCESS_DIR/sync-500000.log.attempt-1.failed" ]]

# A completed pipeline is idempotent.
run_controller "$SUCCESS_DIR" "$TEST_ROOT/reference.json" > "$TEST_ROOT/resume.log" 2>&1
rg -q 'event=pipeline_already_complete' "$TEST_ROOT/resume.log"

# Seed a second run at the independently validated compact stage and prove that
# an exact-state mismatch stops fail-closed without altering the preserved file.
for file in \
    mainnet-active-v3.chk \
    mainnet-900000-compact-v3.chk \
    state-900000.json \
    manifest-900000.json \
    compact-900000-manifest.json \
    latest-state.json \
    sidecar-binary.sha256 \
    checkpoint-compactor.sha256; do
    cp -- "$SUCCESS_DIR/$file" "$MISMATCH_DIR/$file"
done
printf '%s\n' \
    '{"format":1,"height":900001,"block_hash":"wrong-hash","num_leaves":900001,"roots":["root-900001"]}' \
    > "$TEST_ROOT/reference-mismatch.json"
set +e
run_controller "$MISMATCH_DIR" "$TEST_ROOT/reference-mismatch.json" \
    > "$TEST_ROOT/mismatch.log" 2>&1
mismatch_status=$?
set -e
[[ $mismatch_status == 2 ]]
jq -e '.state == "failed" and .stage == "sync-900001"' \
    "$MISMATCH_DIR/pipeline-status.json" >/dev/null
[[ ! -e "$MISMATCH_DIR/rebuild-validation-manifest.json" ]]
[[ $(< "$MISMATCH_DIR/mainnet-900000-compact-v3.chk") == 900000 ]]
rg -q 'reference_validation.*status=mismatch' "$MISMATCH_DIR/sync-900001.log"

# Exercise the real tmux handoff path when the environment permits access to a
# tmux server. Sandboxes that deny the tmux socket still run all controller tests.
TMUX_PROBE=utreexo-handoff-probe-$$
if tmux new-session -d -s "$TMUX_PROBE" true 2>/dev/null; then
    tmux kill-session -t "$TMUX_PROBE" 2>/dev/null || true
    UTREEXO_REBUILD_TMUX_SESSION="$HANDOFF_CONTROLLER_SESSION" \
    UTREEXO_BINARY="$BIN_DIR/fake-sidecar-old" \
    UTREEXO_COMPACTOR="$BIN_DIR/fake-compactor" \
    UTREEXO_BITCOIN_CLI="$BIN_DIR/fake-bitcoin-cli" \
    UTREEXO_RPC_COOKIE="$TEST_ROOT/cookie" \
    UTREEXO_REBUILD_RUN_DIR="$HANDOFF_DIR" \
    UTREEXO_REBUILD_REFERENCE_STATE="$TEST_ROOT/reference.json" \
    UTREEXO_REBUILD_MAX_ATTEMPTS=2 \
    UTREEXO_REBUILD_RETRY_DELAY_SECONDS=0 \
    UTREEXO_REBUILD_MIN_FREE_GIB=1 \
    UTREEXO_CHECKPOINT_SHA256=1 \
        "$SIDECAR_DIR/tools/mainnet-rebuild-validate.sh" start 900001 \
        > "$TEST_ROOT/handoff-start.log"

    for ((attempt = 0; attempt < 100; ++attempt)); do
        if [[ -s "$HANDOFF_DIR/sidecar.pid" ]] &&
           jq -e '.state == "running" and .stage == "sync-250000"' \
               "$HANDOFF_DIR/pipeline-status.json" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    [[ -s "$HANDOFF_DIR/sidecar.pid" ]]

    UTREEXO_REBUILD_TMUX_SESSION="$HANDOFF_CONTROLLER_SESSION" \
    UTREEXO_BINARY_HANDOFF_TMUX_SESSION="$HANDOFF_WATCH_SESSION" \
    UTREEXO_REBUILD_RUN_DIR="$HANDOFF_DIR" \
        "$SIDECAR_DIR/tools/mainnet-binary-handoff.sh" start \
        "$BIN_DIR/fake-sidecar-new" > "$TEST_ROOT/handoff-schedule.log"

    for ((attempt = 0; attempt < 300; ++attempt)); do
        [[ -s "$HANDOFF_DIR/rebuild-validation-manifest.json" ]] && break
        sleep 0.1
    done
    jq -e '.status == "validated" and
           ((.sidecar_binary_history.transitions | length) == 1)' \
        "$HANDOFF_DIR/rebuild-validation-manifest.json" >/dev/null
    jq -e '.transitions[0].checkpoint_height == 250000 and
           (.transitions[0].old_sidecar_version | contains("fake-sidecar-old")) and
           (.transitions[0].new_sidecar_version | contains("fake-sidecar-new"))' \
        "$HANDOFF_DIR/sidecar-binary-transitions.json" >/dev/null
    [[ $(< "$HANDOFF_DIR/sidecar-binary.sha256") == \
       $(sha256sum "$BIN_DIR/fake-sidecar-new" | awk '{print $1}') ]]
    [[ $(< "$HANDOFF_DIR/sidecar-binary.path") == \
       $(realpath "$BIN_DIR/fake-sidecar-new") ]]
    rg -q 'event=binary_handoff_completed' "$HANDOFF_DIR/pipeline.log"
else
    echo "Skipping tmux binary-handoff subtest: tmux socket unavailable"
fi

echo "mainnet rebuild pipeline tests passed"
