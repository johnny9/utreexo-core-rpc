#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SIDECAR_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE_DIR=$(cd -- "$SIDECAR_DIR/.." && pwd)

SYNC_SUPERVISOR=$SCRIPT_DIR/mainnet-sync.sh
SESSION_NAME=${UTREEXO_REBUILD_TMUX_SESSION:-utreexo-mainnet-v3}
COMPACTOR=${UTREEXO_COMPACTOR:-$SIDECAR_DIR/build/utreexo-checkpoint-compact}
BITCOIN_CLI=${UTREEXO_BITCOIN_CLI:-bitcoin-cli}
RPC_COOKIE=${UTREEXO_RPC_COOKIE:-/var/lib/bitcoind/.cookie}
CORE_PID_FILE=${UTREEXO_CORE_PID_FILE:-/var/lib/bitcoind/bitcoind.pid}
RUN_DIR=${UTREEXO_REBUILD_RUN_DIR:-$WORKSPACE_DIR/artifacts/mainnet-validation-v3}
BINARY_PATH_FILE=$RUN_DIR/sidecar-binary.path
if [[ -n ${UTREEXO_BINARY:-} ]]; then
    BINARY=$UTREEXO_BINARY
elif [[ -s $BINARY_PATH_FILE ]]; then
    IFS= read -r BINARY < "$BINARY_PATH_FILE"
else
    BINARY=$SIDECAR_DIR/build/utreexo-bridge
fi
REFERENCE_SOURCE=${UTREEXO_REBUILD_REFERENCE_STATE:-$WORKSPACE_DIR/artifacts/mainnet-sync/expected-state-943013-utreexod-main.json}
LOG_LEVEL=${UTREEXO_REBUILD_LOG_LEVEL:-info}
CHECKPOINT_SHA256=${UTREEXO_CHECKPOINT_SHA256:-1}
MAX_ATTEMPTS=${UTREEXO_REBUILD_MAX_ATTEMPTS:-3}
RETRY_DELAY_SECONDS=${UTREEXO_REBUILD_RETRY_DELAY_SECONDS:-60}
MIN_FREE_GIB=${UTREEXO_REBUILD_MIN_FREE_GIB:-80}

ACTIVE_CHECKPOINT=$RUN_DIR/mainnet-active-v3.chk
COMPACT_CHECKPOINT=$RUN_DIR/mainnet-900000-compact-v3.chk
FINAL_CHECKPOINT=$RUN_DIR/mainnet-final-active-v3.chk
PINNED_REFERENCE=$RUN_DIR/reference-state.json
REFERENCE_DIGEST=$RUN_DIR/reference-state.sha256
BINARY_DIGEST=$RUN_DIR/sidecar-binary.sha256
BINARY_TRANSITIONS=$RUN_DIR/sidecar-binary-transitions.json
COMPACTOR_DIGEST=$RUN_DIR/checkpoint-compactor.sha256
LATEST_STATE=$RUN_DIR/latest-state.json
PIPELINE_STATUS=$RUN_DIR/pipeline-status.json
PIPELINE_LOG=$RUN_DIR/pipeline.log
PIPELINE_LOCK=$RUN_DIR/pipeline.lock
COMPACT_MANIFEST=$RUN_DIR/compact-900000-manifest.json
FINAL_MANIFEST=$RUN_DIR/rebuild-validation-manifest.json

COMPACT_HEIGHT=900000
MILESTONES=(250000 500000 800000 "$COMPACT_HEIGHT")

usage()
{
    cat <<EOF
Usage: $(basename "$0") COMMAND [HEIGHT]

Commands:
  start [HEIGHT]    Start or resume the detached rebuild (default: reference height)
  status            Show pipeline stage, checkpoint height, resources, and session state
  follow            Follow the combined pipeline log (Ctrl-C only stops tail)
  attach            Attach to the pipeline tmux session
  help              Show this help

The controller rebuilds format-3 checkpoints at 250000, 500000, 800000, and
900000; compacts and independently reloads the 900000 checkpoint; clones it to a
separate active file; then syncs to HEIGHT and compares the complete state with
the pinned reference JSON. Failed transient RPC stages retry from the last
completed checkpoint. Deterministic failures stop without deleting checkpoints.

Environment overrides:
  UTREEXO_REBUILD_TMUX_SESSION
  UTREEXO_REBUILD_RUN_DIR
  UTREEXO_REBUILD_REFERENCE_STATE
  UTREEXO_REBUILD_LOG_LEVEL              (default: info)
  UTREEXO_REBUILD_MAX_ATTEMPTS           (default: 3)
  UTREEXO_REBUILD_RETRY_DELAY_SECONDS    (default: 60)
  UTREEXO_REBUILD_MIN_FREE_GIB           (default: 80)
  UTREEXO_BINARY
  UTREEXO_COMPACTOR
  UTREEXO_BITCOIN_CLI
  UTREEXO_RPC_COOKIE
  UTREEXO_CORE_PID_FILE
  UTREEXO_CHECKPOINT_SHA256
EOF
}

require_command()
{
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: required command not found: $1" >&2
        return 1
    fi
}

validate_positive_integer()
{
    local name=$1
    local value=$2
    if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < 1 )); then
        echo "Error: $name must be a positive integer" >&2
        return 1
    fi
}

validate_log_level()
{
    case $LOG_LEVEL in
        error|warn|info|debug|trace) ;;
        *)
            echo "Error: UTREEXO_REBUILD_LOG_LEVEL must be error, warn, info, debug, or trace" >&2
            return 1
            ;;
    esac
}

state_projection()
{
    jq -c '{height, block_hash, num_leaves, roots}' "$1"
}

validate_state_file()
{
    local path=$1
    [[ -r "$path" ]] && jq -e \
        '.height >= 0 and (.block_hash | type == "string") and
         (.num_leaves >= 0) and (.roots | type == "array") and
         all(.roots[]; type == "string")' "$path" >/dev/null
}

write_status()
{
    local state=$1
    local stage=$2
    local target=$3
    local attempt=${4:-0}
    local checkpoint=${5:-}
    local detail=${6:-}
    local temporary=$PIPELINE_STATUS.tmp.$$
    jq -n \
        --arg updated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg state "$state" \
        --arg stage "$stage" \
        --arg detail "$detail" \
        --arg checkpoint "$checkpoint" \
        --argjson target_height "$target" \
        --argjson attempt "$attempt" \
        '{updated_at_utc: $updated_at_utc, state: $state, stage: $stage,
          target_height: $target_height, attempt: $attempt,
          checkpoint: $checkpoint, detail: $detail}' > "$temporary"
    mv -- "$temporary" "$PIPELINE_STATUS"
}

pipeline_event()
{
    local event=$1
    shift
    if (( $# > 0 )); then
        printf 'timestamp=%s level=info event=%s %s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$event" "$*"
    else
        printf 'timestamp=%s level=info event=%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$event"
    fi
}

pin_digest()
{
    local path=$1
    local digest_file=$2
    local label=$3
    local current recorded
    current=$(sha256sum -- "$path" | awk '{print $1}')
    if [[ -s "$digest_file" ]]; then
        read -r recorded < "$digest_file"
        if [[ "$recorded" != "$current" ]]; then
            echo "Error: pinned $label changed: $path" >&2
            return 1
        fi
    else
        printf '%s\n' "$current" > "$digest_file"
    fi
}

pin_reference()
{
    local target=$1
    local temporary
    if [[ ! -e "$PINNED_REFERENCE" ]]; then
        if ! validate_state_file "$REFERENCE_SOURCE"; then
            echo "Error: reference state JSON is missing or invalid: $REFERENCE_SOURCE" >&2
            return 1
        fi
        temporary=$PINNED_REFERENCE.tmp.$$
        cp -- "$REFERENCE_SOURCE" "$temporary"
        mv -- "$temporary" "$PINNED_REFERENCE"
    fi
    if ! validate_state_file "$PINNED_REFERENCE"; then
        echo "Error: pinned reference state is invalid: $PINNED_REFERENCE" >&2
        return 1
    fi
    if [[ $(jq -r '.height' "$PINNED_REFERENCE") != "$target" ]]; then
        echo "Error: reference height must equal target $target: $PINNED_REFERENCE" >&2
        return 1
    fi
    pin_digest "$PINNED_REFERENCE" "$REFERENCE_DIGEST" "reference state"
}

core_preflight()
{
    local target=$1
    local blockchain_info old_hash old_block
    blockchain_info=$("$BITCOIN_CLI" -rpccookiefile="$RPC_COOKIE" getblockchaininfo) || {
        echo "Error: Bitcoin Core RPC preflight failed" >&2
        return 1
    }
    if ! jq -e --argjson target "$target" \
        '.chain == "main" and .initialblockdownload == false and .pruned == false and
         .blocks >= $target and .headers >= $target' <<< "$blockchain_info" >/dev/null; then
        echo "Error: Bitcoin Core must be an unpruned, synchronized mainnet node at or above $target" >&2
        return 1
    fi
    old_hash=$("$BITCOIN_CLI" -rpccookiefile="$RPC_COOKIE" getblockhash 100000) || {
        echo "Error: could not fetch the historical undo preflight block hash" >&2
        return 1
    }
    old_block=$("$BITCOIN_CLI" -rpccookiefile="$RPC_COOKIE" getblock "$old_hash" 3) || {
        echo "Error: could not fetch verbosity-3 historical block data" >&2
        return 1
    }
    if ! jq -e \
        '([.tx[1:][]?.vin[]?] | length) > 0 and
         ([.tx[1:][]?.vin[]? | has("prevout")] | all)' <<< "$old_block" >/dev/null; then
        echo "Error: historical undo prevouts are unavailable at height 100000" >&2
        return 1
    fi
}

validate_resume_layout()
{
    local latest_height
    if [[ -e "$FINAL_CHECKPOINT" && ! -e "$COMPACT_CHECKPOINT" ]]; then
        echo "Error: final active checkpoint exists without its preserved compact source" >&2
        return 1
    fi
    if [[ -e "$COMPACT_CHECKPOINT" ]]; then
        if ! validate_state_file "$RUN_DIR/state-$COMPACT_HEIGHT.json" ||
            [[ $(jq -r '.height' "$RUN_DIR/state-$COMPACT_HEIGHT.json") != "$COMPACT_HEIGHT" ]]; then
            echo "Error: compact checkpoint exists without a valid height-$COMPACT_HEIGHT state" >&2
            return 1
        fi
        return 0
    fi
    if [[ -e "$ACTIVE_CHECKPOINT" ]]; then
        if ! validate_state_file "$LATEST_STATE"; then
            echo "Error: active checkpoint exists without a valid latest-state.json" >&2
            return 1
        fi
        latest_height=$(jq -r '.height' "$LATEST_STATE")
        case $latest_height in
            250000|500000|800000|900000) ;;
            *)
                echo "Error: active checkpoint has unsupported resume height $latest_height" >&2
                return 1
                ;;
        esac
    elif [[ -e "$LATEST_STATE" ]]; then
        echo "Error: latest-state.json exists without the active checkpoint" >&2
        return 1
    fi
}

preflight()
{
    local target=$1
    local binary_version available_bytes required_bytes
    require_command tmux
    require_command jq
    require_command sha256sum
    require_command stdbuf
    require_command flock
    require_command rg
    require_command tee
    require_command "$BITCOIN_CLI"
    validate_positive_integer "target height" "$target"
    validate_positive_integer "UTREEXO_REBUILD_MAX_ATTEMPTS" "$MAX_ATTEMPTS"
    validate_positive_integer "UTREEXO_REBUILD_MIN_FREE_GIB" "$MIN_FREE_GIB"
    if [[ ! "$RETRY_DELAY_SECONDS" =~ ^[0-9]+$ ]]; then
        echo "Error: UTREEXO_REBUILD_RETRY_DELAY_SECONDS must be a non-negative integer" >&2
        return 1
    fi
    if (( target <= COMPACT_HEIGHT )); then
        echo "Error: validation target must be above $COMPACT_HEIGHT" >&2
        return 1
    fi
    validate_log_level
    if [[ ! -x "$BINARY" ]]; then
        echo "Error: sidecar binary is missing or not executable: $BINARY" >&2
        return 1
    fi
    if [[ ! -x "$COMPACTOR" ]]; then
        echo "Error: checkpoint compactor is missing or not executable: $COMPACTOR" >&2
        return 1
    fi
    if [[ ! -r "$RPC_COOKIE" ]]; then
        echo "Error: RPC cookie is not readable: $RPC_COOKIE" >&2
        return 1
    fi
    binary_version=$($BINARY --version)
    if [[ "$binary_version" != *"checkpoint_format=3 forest_format=1"* ]]; then
        echo "Error: rebuild requires a checkpoint-format-3, forest-format-1 sidecar: $binary_version" >&2
        return 1
    fi

    mkdir -p -- "$RUN_DIR"
    pin_reference "$target"
    pin_digest "$BINARY" "$BINARY_DIGEST" "sidecar binary"
    pin_digest "$COMPACTOR" "$COMPACTOR_DIGEST" "checkpoint compactor"
    validate_resume_layout
    core_preflight "$target"

    available_bytes=$(df --output=avail -B1 "$RUN_DIR" | awk 'NR == 2 {print $1}')
    required_bytes=$((MIN_FREE_GIB * 1024 * 1024 * 1024))
    if [[ ! "$available_bytes" =~ ^[0-9]+$ ]] || (( available_bytes < required_bytes )); then
        echo "Error: rebuild filesystem needs at least $MIN_FREE_GIB GiB free" >&2
        return 1
    fi
}

target_paths()
{
    local target=$1
    STAGE_LOG=$RUN_DIR/sync-$target.log
    STAGE_STATE=$RUN_DIR/state-$target.json
    STAGE_RESOURCES=$RUN_DIR/resources-$target.tsv
    STAGE_RESULT=$RUN_DIR/result-$target.txt
    STAGE_MANIFEST=$RUN_DIR/manifest-$target.json
}

prepare_stage()
{
    local target=$1
    target_paths "$target"
    printf '%s\n' "$target" > "$RUN_DIR/current-target"
    : > "$STAGE_LOG"
    : > "$STAGE_RESOURCES"
    rm -f -- "$STAGE_STATE" "$STAGE_RESULT" "$STAGE_MANIFEST" "$RUN_DIR/sidecar.pid"
}

archive_failed_attempt()
{
    local target=$1
    local attempt=$2
    local path destination
    target_paths "$target"
    for path in "$STAGE_LOG" "$STAGE_STATE" "$STAGE_RESOURCES" "$STAGE_RESULT" "$STAGE_MANIFEST"; do
        if [[ -e "$path" ]]; then
            destination=$path.attempt-$attempt.failed
            if [[ -e "$destination" ]]; then
                destination=$destination.$(date -u +%Y%m%dT%H%M%SZ).$$
            fi
            mv -- "$path" "$destination"
        fi
    done
}

transient_stage_failure()
{
    local log=$1
    if rg -q 'event=(checkpoint_load_failed|checkpoint_save_failed|state_json_failed|memory_allocation_failed|sync_aborted_memory_limit)|active-chain reorganization' "$log"; then
        return 1
    fi
    rg -q 'event=(rpc_call_failed|rpc_response_invalid|core_tip_failed)' "$log"
}

run_stage()
{
    local target=$1
    local checkpoint=$2
    local reference=${3:-}
    local attempt exit_status
    for ((attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt)); do
        pin_digest "$BINARY" "$BINARY_DIGEST" "sidecar binary"
        if [[ -n "$reference" ]]; then
            pin_digest "$reference" "$REFERENCE_DIGEST" "reference state"
        fi
        prepare_stage "$target"
        write_status running "sync-$target" "$target" "$attempt" "$checkpoint" "syncing milestone"
        pipeline_event stage_started "height=$target attempt=$attempt checkpoint=$(printf '%q' "$checkpoint")"
        set +e
        env \
            UTREEXO_TMUX_SESSION="$SESSION_NAME" \
            UTREEXO_BINARY="$BINARY" \
            UTREEXO_RPC_COOKIE="$RPC_COOKIE" \
            UTREEXO_CORE_PID_FILE="$CORE_PID_FILE" \
            UTREEXO_RUN_DIR="$RUN_DIR" \
            UTREEXO_CHECKPOINT="$checkpoint" \
            UTREEXO_LOG_LEVEL="$LOG_LEVEL" \
            UTREEXO_CHECKPOINT_SHA256="$CHECKPOINT_SHA256" \
            UTREEXO_REFERENCE_STATE="$reference" \
            "$SYNC_SUPERVISOR" run "$target"
        exit_status=$?
        set -e
        if (( exit_status == 0 )); then
            if [[ ! -s "$checkpoint" ]] || ! validate_state_file "$STAGE_STATE" ||
                [[ $(jq -r '.height' "$STAGE_STATE") != "$target" ]]; then
                write_status failed "sync-$target" "$target" "$attempt" "$checkpoint" \
                    "successful process did not publish the expected checkpoint state"
                return 1
            fi
            pipeline_event stage_completed "height=$target attempt=$attempt"
            return 0
        fi

        if (( exit_status != 2 )) && transient_stage_failure "$STAGE_LOG" &&
            (( attempt < MAX_ATTEMPTS )); then
            pipeline_event stage_retry_scheduled \
                "height=$target attempt=$attempt exit_status=$exit_status delay_seconds=$RETRY_DELAY_SECONDS"
            archive_failed_attempt "$target" "$attempt"
            write_status retrying "sync-$target" "$target" "$attempt" "$checkpoint" \
                "transient RPC failure; retry scheduled"
            sleep "$RETRY_DELAY_SECONDS"
            continue
        fi

        write_status failed "sync-$target" "$target" "$attempt" "$checkpoint" \
            "stage failed with exit status $exit_status"
        pipeline_event stage_failed "height=$target attempt=$attempt exit_status=$exit_status"
        return "$exit_status"
    done
}

verify_compact_checkpoint()
{
    local target=$1
    local validation_log=$RUN_DIR/compact-900000-validation.log
    local validation_state=$RUN_DIR/compact-900000-validation-state.json
    local clone_temporary=$FINAL_CHECKPOINT.clone.$$
    local exit_status expected actual compact_sha source_sha

    write_status running compact-validation "$target" 0 "$COMPACT_CHECKPOINT" \
        "cloning and independently loading compact checkpoint"
    cp --reflink=auto -- "$COMPACT_CHECKPOINT" "$clone_temporary"
    mv -f -- "$clone_temporary" "$FINAL_CHECKPOINT"
    : > "$validation_log"
    rm -f -- "$validation_state"
    pipeline_event compact_validation_started \
        "source=$(printf '%q' "$COMPACT_CHECKPOINT") clone=$(printf '%q' "$FINAL_CHECKPOINT")"
    set +e
    stdbuf -oL -eL "$BINARY" \
        --rpc-cookie="$RPC_COOKIE" \
        --checkpoint="$FINAL_CHECKPOINT" \
        --state-json="$validation_state" \
        --stop-height="$COMPACT_HEIGHT" \
        --log-level="$LOG_LEVEL" \
        > >(tee -a "$validation_log") 2>&1
    exit_status=$?
    set -e
    if (( exit_status != 0 )) || ! validate_state_file "$validation_state"; then
        write_status failed compact-validation "$target" 0 "$COMPACT_CHECKPOINT" \
            "compact checkpoint reload failed with exit status $exit_status"
        return 1
    fi
    expected=$(state_projection "$RUN_DIR/state-$COMPACT_HEIGHT.json")
    actual=$(state_projection "$validation_state")
    if [[ "$actual" != "$expected" ]]; then
        write_status failed compact-validation "$target" 0 "$COMPACT_CHECKPOINT" \
            "compact checkpoint state does not match the height-$COMPACT_HEIGHT source"
        pipeline_event compact_validation_failed \
            "reason=state_mismatch expected=$expected actual=$actual"
        return 1
    fi

    compact_sha=$(sha256sum -- "$COMPACT_CHECKPOINT" | awk '{print $1}')
    source_sha=$(jq -r '.checkpoint_sha256' "$RUN_DIR/manifest-$COMPACT_HEIGHT.json")
    jq -n \
        --arg created_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg source "$ACTIVE_CHECKPOINT" \
        --arg compact "$COMPACT_CHECKPOINT" \
        --arg active_clone "$FINAL_CHECKPOINT" \
        --arg source_sha256 "$source_sha" \
        --arg compact_sha256 "$compact_sha" \
        --argjson source_bytes "$(stat -c '%s' "$ACTIVE_CHECKPOINT")" \
        --argjson compact_bytes "$(stat -c '%s' "$COMPACT_CHECKPOINT")" \
        --argjson state "$expected" \
        '{created_at_utc: $created_at_utc, source: $source, compact: $compact,
          active_clone: $active_clone, source_bytes: $source_bytes,
          compact_bytes: $compact_bytes, source_sha256: $source_sha256,
          compact_sha256: $compact_sha256, roots_verified_by_compactor: true,
          reload_state_verified: true, state: $state}' > "$COMPACT_MANIFEST.tmp.$$"
    mv -- "$COMPACT_MANIFEST.tmp.$$" "$COMPACT_MANIFEST"
    pipeline_event compact_validation_completed \
        "height=$COMPACT_HEIGHT sha256=$compact_sha"
}

compact_checkpoint()
{
    local target=$1
    local exit_status
    write_status running compaction "$target" 0 "$ACTIVE_CHECKPOINT" \
        "compacting height-$COMPACT_HEIGHT checkpoint"
    pipeline_event compaction_started \
        "height=$COMPACT_HEIGHT source=$(printf '%q' "$ACTIVE_CHECKPOINT") destination=$(printf '%q' "$COMPACT_CHECKPOINT")"
    if [[ -e "$COMPACT_CHECKPOINT" ]]; then
        echo "Error: compact destination already exists without a validation manifest" >&2
        return 1
    fi
    pin_digest "$COMPACTOR" "$COMPACTOR_DIGEST" "checkpoint compactor"
    rm -f -- "$COMPACT_CHECKPOINT.tmp" "$COMPACT_CHECKPOINT.node-map.tmp"
    set +e
    "$COMPACTOR" "$ACTIVE_CHECKPOINT" "$COMPACT_CHECKPOINT"
    exit_status=$?
    set -e
    if (( exit_status != 0 )); then
        write_status failed compaction "$target" 0 "$ACTIVE_CHECKPOINT" \
            "checkpoint compactor failed with exit status $exit_status"
        return "$exit_status"
    fi
    pipeline_event compaction_completed "height=$COMPACT_HEIGHT"
    verify_compact_checkpoint "$target"
}

write_final_manifest()
{
    local target=$1
    local binary_sha reference_sha binary_transitions
    read -r binary_sha < "$BINARY_DIGEST"
    read -r reference_sha < "$REFERENCE_DIGEST"
    binary_transitions='{"format":1,"transitions":[]}'
    if [[ -s "$BINARY_TRANSITIONS" ]]; then
        binary_transitions=$(jq -c . "$BINARY_TRANSITIONS")
    fi
    jq -n \
        --arg completed_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg run_dir "$RUN_DIR" \
        --arg preserved_checkpoint "$COMPACT_CHECKPOINT" \
        --arg final_checkpoint "$FINAL_CHECKPOINT" \
        --arg sidecar_binary_sha256 "$binary_sha" \
        --arg reference_state_sha256 "$reference_sha" \
        --argjson sidecar_binary_history "$binary_transitions" \
        --argjson target_height "$target" \
        --slurpfile compact "$COMPACT_MANIFEST" \
        --slurpfile final "$RUN_DIR/manifest-$target.json" \
        '{completed_at_utc: $completed_at_utc, status: "validated",
          target_height: $target_height, run_dir: $run_dir,
          preserved_checkpoint: $preserved_checkpoint,
          final_checkpoint: $final_checkpoint,
          sidecar_binary_sha256: $sidecar_binary_sha256,
          sidecar_binary_history: $sidecar_binary_history,
          reference_state_sha256: $reference_state_sha256,
          compact_checkpoint: $compact[0], final_state: $final[0]}' \
        > "$FINAL_MANIFEST.tmp.$$"
    mv -- "$FINAL_MANIFEST.tmp.$$" "$FINAL_MANIFEST"
}

pipeline_exit_trap()
{
    local exit_status=$?
    local recorded_state=unknown
    trap - EXIT
    if (( exit_status != 0 )); then
        if [[ -s "$PIPELINE_STATUS" ]]; then
            recorded_state=$(jq -r '.state // "unknown"' "$PIPELINE_STATUS" 2>/dev/null || echo unknown)
        fi
        if [[ "$recorded_state" != failed ]]; then
            write_status failed controller "$PIPELINE_TARGET" 0 "" \
                "controller exited unexpectedly with status $exit_status" || true
        fi
        pipeline_event pipeline_failed "target_height=$PIPELINE_TARGET exit_status=$exit_status" || true
    fi
    exit "$exit_status"
}

run_pipeline()
{
    local target=$1
    local milestone current_height=0
    PIPELINE_TARGET=$target
    trap pipeline_exit_trap EXIT
    exec 9> "$PIPELINE_LOCK"
    if ! flock -n 9; then
        echo "Error: another rebuild controller holds $PIPELINE_LOCK" >&2
        return 1
    fi
    preflight "$target"
    pipeline_event pipeline_started \
        "target_height=$target run_dir=$(printf '%q' "$RUN_DIR") binary=$($BINARY --version)"

    if [[ -s "$FINAL_MANIFEST" ]] &&
        jq -e --argjson target "$target" \
            '.status == "validated" and .target_height == $target' "$FINAL_MANIFEST" >/dev/null; then
        write_status complete validation "$target" 0 "$FINAL_CHECKPOINT" "already validated"
        pipeline_event pipeline_already_complete "target_height=$target"
        return 0
    fi

    if [[ ! -e "$COMPACT_CHECKPOINT" ]]; then
        if [[ -s "$LATEST_STATE" ]]; then
            current_height=$(jq -r '.height' "$LATEST_STATE")
        fi
        for milestone in "${MILESTONES[@]}"; do
            if (( current_height >= milestone )); then
                pipeline_event stage_skipped "height=$milestone resume_height=$current_height"
                continue
            fi
            run_stage "$milestone" "$ACTIVE_CHECKPOINT"
            current_height=$milestone
        done
        compact_checkpoint "$target"
    elif [[ ! -s "$COMPACT_MANIFEST" ]]; then
        verify_compact_checkpoint "$target"
    else
        local recorded_compact_sha current_compact_sha
        recorded_compact_sha=$(jq -r '.compact_sha256' "$COMPACT_MANIFEST")
        current_compact_sha=$(sha256sum -- "$COMPACT_CHECKPOINT" | awk '{print $1}')
        if [[ "$recorded_compact_sha" != "$current_compact_sha" ]]; then
            write_status failed compact-validation "$target" 0 "$COMPACT_CHECKPOINT" \
                "preserved compact checkpoint digest changed"
            return 1
        fi
        if [[ ! -e "$FINAL_CHECKPOINT" ]]; then
            local clone_temporary=$FINAL_CHECKPOINT.clone.$$
            cp --reflink=auto -- "$COMPACT_CHECKPOINT" "$clone_temporary"
            mv -- "$clone_temporary" "$FINAL_CHECKPOINT"
        fi
        pipeline_event compact_stage_skipped "reason=validated_resume"
    fi

    run_stage "$target" "$FINAL_CHECKPOINT" "$PINNED_REFERENCE"
    if [[ $(jq -r '.reference_validation' "$RUN_DIR/manifest-$target.json") != match ]]; then
        write_status failed validation "$target" 0 "$FINAL_CHECKPOINT" \
            "final manifest did not record an exact reference match"
        return 2
    fi
    write_final_manifest "$target"
    write_status complete validation "$target" 0 "$FINAL_CHECKPOINT" \
        "height, block hash, leaf count, and ordered roots match the pinned reference"
    pipeline_event pipeline_completed \
        "target_height=$target preserved_checkpoint=$(printf '%q' "$COMPACT_CHECKPOINT") final_checkpoint=$(printf '%q' "$FINAL_CHECKPOINT")"
}

start_pipeline()
{
    local target=${1:-}
    local command
    require_command jq
    if [[ -z "$target" ]]; then
        if validate_state_file "$PINNED_REFERENCE"; then
            target=$(jq -r '.height' "$PINNED_REFERENCE")
        elif validate_state_file "$REFERENCE_SOURCE"; then
            target=$(jq -r '.height' "$REFERENCE_SOURCE")
        else
            echo "Error: start needs HEIGHT when the reference state cannot be read" >&2
            return 1
        fi
    fi
    preflight "$target"
    if tmux has-session -t "=$SESSION_NAME" 2>/dev/null; then
        echo "Error: tmux session already exists: $SESSION_NAME" >&2
        return 1
    fi
    if [[ -s "$FINAL_MANIFEST" ]] && jq -e --argjson target "$target" \
        '.status == "validated" and .target_height == $target' "$FINAL_MANIFEST" >/dev/null; then
        echo "Validation is already complete: $FINAL_MANIFEST"
        return 0
    fi
    : >> "$PIPELINE_LOG"
    write_status starting preflight "$target" 0 "" "launching detached controller"
    printf -v command 'exec %q internal-run %q >> %q 2>&1' \
        "$SCRIPT_DIR/mainnet-rebuild-validate.sh" "$target" "$PIPELINE_LOG"
    tmux new-session -d -s "$SESSION_NAME" -c "$WORKSPACE_DIR" \
        -e "UTREEXO_REBUILD_TMUX_SESSION=$SESSION_NAME" \
        -e "UTREEXO_REBUILD_RUN_DIR=$RUN_DIR" \
        -e "UTREEXO_REBUILD_REFERENCE_STATE=$REFERENCE_SOURCE" \
        -e "UTREEXO_REBUILD_LOG_LEVEL=$LOG_LEVEL" \
        -e "UTREEXO_REBUILD_MAX_ATTEMPTS=$MAX_ATTEMPTS" \
        -e "UTREEXO_REBUILD_RETRY_DELAY_SECONDS=$RETRY_DELAY_SECONDS" \
        -e "UTREEXO_REBUILD_MIN_FREE_GIB=$MIN_FREE_GIB" \
        -e "UTREEXO_BINARY=$BINARY" \
        -e "UTREEXO_COMPACTOR=$COMPACTOR" \
        -e "UTREEXO_BITCOIN_CLI=$BITCOIN_CLI" \
        -e "UTREEXO_RPC_COOKIE=$RPC_COOKIE" \
        -e "UTREEXO_CORE_PID_FILE=$CORE_PID_FILE" \
        -e "UTREEXO_CHECKPOINT_SHA256=$CHECKPOINT_SHA256" \
        "$command"

    echo "Started unattended rebuild session: $SESSION_NAME"
    echo "Target height: $target"
    echo "Run directory: $RUN_DIR"
    echo "Preserved 900000 checkpoint: $COMPACT_CHECKPOINT"
    echo "Monitor: $SYNC_SUPERVISOR rebuild-status"
    echo "Live log: $SYNC_SUPERVISOR rebuild-follow"
}

show_status()
{
    require_command jq
    require_command tmux
    if tmux has-session -t "=$SESSION_NAME" 2>/dev/null; then
        echo "session=$SESSION_NAME state=running"
    else
        echo "session=$SESSION_NAME state=stopped"
    fi
    if [[ -s "$PIPELINE_STATUS" ]]; then
        jq . "$PIPELINE_STATUS"
    else
        echo "pipeline=not_started run_dir=$RUN_DIR"
    fi
    if [[ -s "$LATEST_STATE" ]]; then
        jq '{height, block_hash, num_leaves}' "$LATEST_STATE"
    fi
    if [[ -s "$RUN_DIR/current-target" ]]; then
        local target
        read -r target < "$RUN_DIR/current-target"
        if [[ -s "$RUN_DIR/resources-$target.tsv" ]]; then
            local sample
            sample=$(tail -n 1 "$RUN_DIR/resources-$target.tsv")
            [[ "$sample" != timestamp_utc* ]] && printf '%s\n' "$sample"
        fi
    fi
    if [[ -d "$RUN_DIR" ]]; then
        df -h "$RUN_DIR" | tail -n 1
    fi
}

follow_log()
{
    mkdir -p -- "$RUN_DIR"
    touch "$PIPELINE_LOG"
    exec tail -n 60 -F "$PIPELINE_LOG"
}

attach_session()
{
    require_command tmux
    if ! tmux has-session -t "=$SESSION_NAME" 2>/dev/null; then
        echo "Error: tmux session is not running: $SESSION_NAME" >&2
        return 1
    fi
    exec tmux attach-session -t "=$SESSION_NAME"
}

case ${1:-help} in
    start) start_pipeline "${2:-}" ;;
    internal-run) run_pipeline "${2:-}" ;;
    status) show_status ;;
    follow) follow_log ;;
    attach) attach_session ;;
    help|-h|--help) usage ;;
    *) echo "Error: unknown command: $1" >&2; usage >&2; exit 1 ;;
esac
