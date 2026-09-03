#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SIDECAR_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE_DIR=$(cd -- "$SIDECAR_DIR/.." && pwd)

SESSION_NAME=${UTREEXO_TMUX_SESSION:-utreexo-mainnet}
BINARY=${UTREEXO_BINARY:-$SIDECAR_DIR/build/utreexo-bridge}
RPC_COOKIE=${UTREEXO_RPC_COOKIE:-/var/lib/bitcoind/.cookie}
CORE_PID_FILE=${UTREEXO_CORE_PID_FILE:-/var/lib/bitcoind/bitcoind.pid}
RUN_DIR=${UTREEXO_RUN_DIR:-$WORKSPACE_DIR/artifacts/mainnet-sync}
CHECKPOINT=${UTREEXO_CHECKPOINT:-$RUN_DIR/mainnet.chk}
LOG_LEVEL=${UTREEXO_LOG_LEVEL:-debug}
CHECKPOINT_SHA256=${UTREEXO_CHECKPOINT_SHA256:-1}
REFERENCE_STATE=${UTREEXO_REFERENCE_STATE:-}
LATEST_STATE=$RUN_DIR/latest-state.json
CURRENT_TARGET=$RUN_DIR/current-target
PID_FILE=$RUN_DIR/sidecar.pid

usage()
{
    cat <<EOF
Usage: $(basename "$0") COMMAND [ARGUMENT]

Commands:
  start HEIGHT       Start a detached tmux sync to an explicit milestone height
  rebuild-validate [HEIGHT]
                     Start/resume the unattended format-3 rebuild, 900000
                     compaction, and exact reference validation pipeline
  rebuild-status     Show unattended rebuild pipeline status
  rebuild-follow     Follow the unattended rebuild pipeline log
  rebuild-attach     Attach to the unattended rebuild tmux session
  rebuild-handoff-binary PATH
                     Switch to PATH after the active rebuild stage checkpoints
  status             Show session, height, memory, disk, and last-run status
  follow             Follow the current run log (Ctrl-C only stops tail)
  attach             Attach to the tmux session (detach with Ctrl-b, then d)
  init CHECKPOINT [STATE_JSON]
                     Initialize from an existing checkpoint and optional state JSON
  help               Show this help

Environment overrides:
  UTREEXO_TMUX_SESSION  tmux session name (default: utreexo-mainnet)
  UTREEXO_BINARY        sidecar executable
  UTREEXO_RPC_COOKIE    Bitcoin Core cookie path
  UTREEXO_CORE_PID_FILE Bitcoin Core pid file used for RSS monitoring
  UTREEXO_RUN_DIR       logs/checkpoint directory
  UTREEXO_CHECKPOINT    checkpoint path
  UTREEXO_LOG_LEVEL     sidecar log level (default: debug)
  UTREEXO_CHECKPOINT_SHA256
                        hash successful milestone checkpoints (default: 1)
  UTREEXO_REFERENCE_STATE
                        optional expected state JSON; a mismatch makes the run fail

Do not press Ctrl-C in the attached sync window: the sidecar cannot checkpoint on
signals yet. Detach with Ctrl-b, then d, and let the milestone complete.
EOF
}

require_command()
{
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: required command not found: $1" >&2
        exit 1
    fi
}

log_level_rank()
{
    case $1 in
        error) echo 0 ;;
        warn) echo 1 ;;
        info) echo 2 ;;
        debug) echo 3 ;;
        trace) echo 4 ;;
        *) return 1 ;;
    esac
}

supervisor_log()
{
    local level=$1
    local event=$2
    local fields=${3:-}
    local configured_rank event_rank
    configured_rank=$(log_level_rank "$LOG_LEVEL") || return 0
    event_rank=$(log_level_rank "$level") || return 0
    if (( event_rank <= configured_rank )); then
        printf 'timestamp=%s level=%s event=%s%s%s\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$event" \
            "${fields:+ }" "$fields" >> "$LOG_FILE"
    fi
}

core_rss_kib()
{
    local core_pid
    if [[ -r "$CORE_PID_FILE" ]]; then
        read -r core_pid < "$CORE_PID_FILE"
        if [[ "$core_pid" =~ ^[0-9]+$ ]]; then
            ps -o rss= -p "$core_pid" 2>/dev/null | awk '{print $1 + 0}'
            return
        fi
    fi
    echo 0
}

read_target()
{
    if [[ -s "$CURRENT_TARGET" ]]; then
        tr -d '[:space:]' < "$CURRENT_TARGET"
    fi
}

paths_for_target()
{
    local target=$1
    LOG_FILE=$RUN_DIR/sync-$target.log
    STATE_FILE=$RUN_DIR/state-$target.json
    RESOURCE_FILE=$RUN_DIR/resources-$target.tsv
    RESULT_FILE=$RUN_DIR/result-$target.txt
    MANIFEST_FILE=$RUN_DIR/manifest-$target.json
}

initialize_checkpoint()
{
    local source=${1:-}
    local state_source=${2:-}
    require_command tmux
    require_command jq
    if [[ -z "$source" || ! -f "$source" ]]; then
        echo "Error: init requires an existing checkpoint file" >&2
        exit 1
    fi
    if tmux has-session -t "=$SESSION_NAME" 2>/dev/null; then
        echo "Error: cannot replace the checkpoint while $SESSION_NAME is running" >&2
        exit 1
    fi
    mkdir -p -- "$RUN_DIR"
    if [[ -e "$CHECKPOINT" ]]; then
        echo "Error: checkpoint already exists: $CHECKPOINT" >&2
        exit 1
    fi
    if [[ -n "$state_source" ]]; then
        if [[ ! -f "$state_source" ]] || ! jq -e \
            '.height >= 0 and (.block_hash | type == "string") and (.num_leaves >= 0)' \
            "$state_source" >/dev/null; then
            echo "Error: state JSON is missing or invalid: $state_source" >&2
            exit 1
        fi
    fi
    cp --reflink=auto -- "$source" "$CHECKPOINT"
    if [[ -n "$state_source" ]]; then
        cp -- "$state_source" "$LATEST_STATE"
    fi
    echo "Initialized $CHECKPOINT from $source"
    [[ -n "$state_source" ]] && echo "Initialized $LATEST_STATE from $state_source"
}

start_sync()
{
    local target=${1:-}
    require_command tmux
    require_command stdbuf
    require_command jq
    if [[ "$CHECKPOINT_SHA256" == 1 ]]; then require_command sha256sum; fi

    if [[ ! "$target" =~ ^[0-9]+$ ]]; then
        echo "Error: start requires a numeric milestone height" >&2
        exit 1
    fi
    if ! log_level_rank "$LOG_LEVEL" >/dev/null; then
        echo "Error: invalid UTREEXO_LOG_LEVEL (expected error, warn, info, debug, or trace)" >&2
        exit 1
    fi
    if [[ ! -x "$BINARY" ]]; then
        echo "Error: sidecar binary is missing or not executable: $BINARY" >&2
        exit 1
    fi
    if [[ ! -r "$RPC_COOKIE" ]]; then
        echo "Error: RPC cookie is not readable: $RPC_COOKIE" >&2
        exit 1
    fi
    if [[ -n "$REFERENCE_STATE" ]] && { [[ ! -r "$REFERENCE_STATE" ]] || ! jq -e \
        '.height >= 0 and (.block_hash | type == "string") and (.num_leaves >= 0) and
         (.roots | type == "array")' "$REFERENCE_STATE" >/dev/null; }; then
        echo "Error: reference state JSON is missing or invalid: $REFERENCE_STATE" >&2
        exit 1
    fi
    if [[ -n "$REFERENCE_STATE" ]] && [[ $(jq -r '.height' "$REFERENCE_STATE") != "$target" ]]; then
        echo "Error: reference state height must equal target $target: $REFERENCE_STATE" >&2
        exit 1
    fi
    if [[ ! -f "$CHECKPOINT" ]]; then
        echo "Error: checkpoint not found: $CHECKPOINT" >&2
        echo "Initialize it first with: $(basename "$0") init PATH" >&2
        exit 1
    fi
    if tmux has-session -t "=$SESSION_NAME" 2>/dev/null; then
        echo "Error: tmux session already exists: $SESSION_NAME" >&2
        exit 1
    fi
    if [[ -s "$LATEST_STATE" ]]; then
        local current_height
        current_height=$(jq -r '.height' "$LATEST_STATE")
        if (( target <= current_height )); then
            echo "Error: target $target must be above checkpoint height $current_height" >&2
            exit 1
        fi
    fi

    mkdir -p -- "$RUN_DIR"
    printf '%s\n' "$target" > "$CURRENT_TARGET"
    paths_for_target "$target"
    : > "$LOG_FILE"
    : > "$RESOURCE_FILE"
    rm -f -- "$RESULT_FILE" "$STATE_FILE" "$MANIFEST_FILE" "$PID_FILE"

    tmux new-session -d -s "$SESSION_NAME" -c "$WORKSPACE_DIR" \
        -e "UTREEXO_TMUX_SESSION=$SESSION_NAME" \
        -e "UTREEXO_BINARY=$BINARY" \
        -e "UTREEXO_RPC_COOKIE=$RPC_COOKIE" \
        -e "UTREEXO_CORE_PID_FILE=$CORE_PID_FILE" \
        -e "UTREEXO_RUN_DIR=$RUN_DIR" \
        -e "UTREEXO_CHECKPOINT=$CHECKPOINT" \
        -e "UTREEXO_LOG_LEVEL=$LOG_LEVEL" \
        -e "UTREEXO_CHECKPOINT_SHA256=$CHECKPOINT_SHA256" \
        -e "UTREEXO_REFERENCE_STATE=$REFERENCE_STATE" \
        "$SCRIPT_DIR/mainnet-sync.sh run $target"

    echo "Started tmux session: $SESSION_NAME"
    echo "Target height: $target"
    echo "Checkpoint: $CHECKPOINT"
    echo "Monitor: $SCRIPT_DIR/mainnet-sync.sh status"
    echo "Live log: $SCRIPT_DIR/mainnet-sync.sh follow"
    echo "Attach: $SCRIPT_DIR/mainnet-sync.sh attach"
}

run_sync()
{
    local target=${1:-}
    if [[ ! "$target" =~ ^[0-9]+$ ]]; then
        echo "Error: internal run requires a numeric target" >&2
        exit 1
    fi
    mkdir -p -- "$RUN_DIR"
    paths_for_target "$target"

    local start_epoch end_epoch sidecar_pid sampler_pid exit_status sidecar_exit_status
    local reference_validation expected_state actual_state
    start_epoch=$(date +%s)
    {
        echo "started_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "target_height=$target"
        echo "checkpoint=$CHECKPOINT"
    } >> "$LOG_FILE"

    stdbuf -oL -eL "$BINARY" \
        --rpc-cookie="$RPC_COOKIE" \
        --checkpoint="$CHECKPOINT" \
        --allow-untrusted-checkpoint \
        --fast-sync \
        --state-json="$STATE_FILE" \
        --stop-height="$target" \
        --log-level="$LOG_LEVEL" \
        > >(tee -a "$LOG_FILE") 2>&1 &
    sidecar_pid=$!
    printf '%s\n' "$sidecar_pid" > "$PID_FILE"

    (
        printf 'timestamp_utc\tsidecar_rss_kib\tsidecar_hwm_kib\tsidecar_pss_kib\tcore_rss_kib\tmem_available_kib\tswap_free_kib\tpswpin_pages\tpswpout_pages\tsidecar_minflt\tsidecar_majflt\tsidecar_user_ticks\tsidecar_system_ticks\tsidecar_read_bytes\tsidecar_write_bytes\n'
        local_warning_active=0
        while kill -0 "$sidecar_pid" 2>/dev/null; do
            local_sidecar_rss=$(awk '/VmRSS:/ {print $2}' "/proc/$sidecar_pid/status" 2>/dev/null || true)
            local_sidecar_hwm=$(awk '/VmHWM:/ {print $2}' "/proc/$sidecar_pid/status" 2>/dev/null || true)
            if (( ${local_sidecar_hwm:-0} < ${local_sidecar_rss:-0} )); then
                local_sidecar_hwm=${local_sidecar_rss:-0}
            fi
            local_sidecar_pss=$(awk '/^Pss:/ {print $2}' "/proc/$sidecar_pid/smaps_rollup" 2>/dev/null || true)
            local_core_rss=$(core_rss_kib)
            local_mem_available=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
            local_swap_free=$(awk '/SwapFree:/ {print $2}' /proc/meminfo)
            local_pswpin=$(awk '$1 == "pswpin" {print $2}' /proc/vmstat)
            local_pswpout=$(awk '$1 == "pswpout" {print $2}' /proc/vmstat)
            read -r local_minflt local_majflt local_user_ticks local_system_ticks < <(
                awk '{print $10, $12, $14, $15}' "/proc/$sidecar_pid/stat" 2>/dev/null || echo '0 0 0 0'
            )
            local_read_bytes=$(awk '$1 == "read_bytes:" {print $2}' "/proc/$sidecar_pid/io" 2>/dev/null || true)
            local_write_bytes=$(awk '$1 == "write_bytes:" {print $2}' "/proc/$sidecar_pid/io" 2>/dev/null || true)
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                "${local_sidecar_rss:-0}" "${local_sidecar_hwm:-0}" "${local_sidecar_pss:-0}" \
                "$local_core_rss" "$local_mem_available" "$local_swap_free" \
                "${local_pswpin:-0}" "${local_pswpout:-0}" \
                "${local_minflt:-0}" "${local_majflt:-0}" \
                "${local_user_ticks:-0}" "${local_system_ticks:-0}" \
                "${local_read_bytes:-0}" "${local_write_bytes:-0}"
            if (( local_mem_available < 4 * 1024 * 1024 )); then
                if (( local_warning_active == 0 )); then
                    supervisor_log warn memory_pressure \
                        "mem_available_kib=$local_mem_available swap_free_kib=$local_swap_free"
                    local_warning_active=1
                fi
            elif (( local_warning_active != 0 )); then
                supervisor_log info memory_pressure_recovered \
                    "mem_available_kib=$local_mem_available swap_free_kib=$local_swap_free"
                local_warning_active=0
            fi
            sleep 1
        done
    ) >> "$RESOURCE_FILE" &
    sampler_pid=$!

    set +e
    wait "$sidecar_pid"
    sidecar_exit_status=$?
    set -e
    wait "$sampler_pid" 2>/dev/null || true
    rm -f -- "$PID_FILE"
    end_epoch=$(date +%s)
    exit_status=$sidecar_exit_status
    reference_validation=not_configured
    expected_state=null
    if (( sidecar_exit_status == 0 )) && [[ -s "$STATE_FILE" && -n "$REFERENCE_STATE" ]]; then
        expected_state=$(jq -c '{height, block_hash, num_leaves, roots}' "$REFERENCE_STATE")
        actual_state=$(jq -c '{height, block_hash, num_leaves, roots}' "$STATE_FILE")
        if [[ "$actual_state" == "$expected_state" ]]; then
            reference_validation=match
            supervisor_log info reference_validation \
                "status=match height=$target expected_state=$expected_state"
        else
            reference_validation=mismatch
            exit_status=2
            supervisor_log error reference_validation \
                "status=mismatch height=$target expected_state=$expected_state actual_state=$actual_state"
        fi
    fi

    local peak_sidecar peak_sidecar_hwm peak_sidecar_pss peak_core minimum_available minimum_swap
    local sidecar_minor_faults sidecar_major_faults sidecar_user_ticks sidecar_system_ticks
    local sidecar_read_bytes sidecar_write_bytes system_pswpin_pages system_pswpout_pages
    peak_sidecar=$(awk 'NR > 1 && $2 > max {max=$2} END {print max + 0}' "$RESOURCE_FILE")
    peak_sidecar_hwm=$(awk 'NR > 1 && $3 > max {max=$3} END {print max + 0}' "$RESOURCE_FILE")
    peak_sidecar_pss=$(awk 'NR > 1 && $4 > max {max=$4} END {print max + 0}' "$RESOURCE_FILE")
    peak_core=$(awk 'NR > 1 && $5 > max {max=$5} END {print max + 0}' "$RESOURCE_FILE")
    minimum_available=$(awk 'NR > 1 && (min == 0 || $6 < min) {min=$6} END {print min + 0}' "$RESOURCE_FILE")
    minimum_swap=$(awk 'NR > 1 && (min == 0 || $7 < min) {min=$7} END {print min + 0}' "$RESOURCE_FILE")
    read -r sidecar_minor_faults sidecar_major_faults sidecar_user_ticks sidecar_system_ticks \
        sidecar_read_bytes sidecar_write_bytes system_pswpin_pages system_pswpout_pages < <(
        awk 'NR == 2 {minflt=$10; majflt=$11; userticks=$12; systicks=$13; readb=$14; writeb=$15; pin=$8; pout=$9}
             NR > 1 {last_minflt=$10; last_majflt=$11; last_user=$12; last_sys=$13; last_readb=$14; last_writeb=$15; last_pin=$8; last_pout=$9}
             END {print last_minflt-minflt, last_majflt-majflt, last_user-userticks, last_sys-systicks,
                        last_readb-readb, last_writeb-writeb, last_pin-pin, last_pout-pout}' "$RESOURCE_FILE"
    )

    {
        echo "exit_status=$exit_status"
        echo "sidecar_exit_status=$sidecar_exit_status"
        echo "reference_validation=$reference_validation"
        echo "target_height=$target"
        echo "elapsed_seconds=$((end_epoch - start_epoch))"
        echo "peak_sidecar_rss_kib=$peak_sidecar"
        echo "peak_sidecar_hwm_kib=$peak_sidecar_hwm"
        echo "peak_sidecar_pss_kib=$peak_sidecar_pss"
        echo "peak_core_rss_kib=$peak_core"
        echo "minimum_mem_available_kib=$minimum_available"
        echo "minimum_swap_free_kib=$minimum_swap"
        echo "sidecar_minor_faults=$sidecar_minor_faults"
        echo "sidecar_major_faults=$sidecar_major_faults"
        echo "sidecar_user_ticks=$sidecar_user_ticks"
        echo "sidecar_system_ticks=$sidecar_system_ticks"
        echo "sidecar_read_bytes=$sidecar_read_bytes"
        echo "sidecar_write_bytes=$sidecar_write_bytes"
        echo "system_pswpin_pages=$system_pswpin_pages"
        echo "system_pswpout_pages=$system_pswpout_pages"
        echo "finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$RESULT_FILE"

    if (( sidecar_exit_status == 0 )) && [[ -s "$STATE_FILE" ]]; then
        local checkpoint_size checkpoint_sha256 sidecar_version
        checkpoint_size=$(stat -c '%s' "$CHECKPOINT")
        checkpoint_sha256="disabled"
        if [[ "$CHECKPOINT_SHA256" == 1 ]]; then
            require_command sha256sum
            checkpoint_sha256=$(sha256sum -- "$CHECKPOINT" | awk '{print $1}')
        fi
        sidecar_version=$("$BINARY" --version)
        {
            echo "checkpoint_size_bytes=$checkpoint_size"
            echo "checkpoint_sha256=$checkpoint_sha256"
        } >> "$RESULT_FILE"
        jq -n \
            --slurpfile state "$STATE_FILE" \
            --arg sidecar_version "$sidecar_version" \
            --arg checkpoint "$CHECKPOINT" \
            --arg checkpoint_sha256 "$checkpoint_sha256" \
            --arg reference_validation "$reference_validation" \
            --argjson expected_state "$expected_state" \
            --argjson checkpoint_size_bytes "$checkpoint_size" \
            '$state[0] + {sidecar_version: $sidecar_version, checkpoint: $checkpoint,
                          checkpoint_size_bytes: $checkpoint_size_bytes,
                          checkpoint_sha256: $checkpoint_sha256,
                          reference_validation: $reference_validation,
                          expected_state: $expected_state}' > "$MANIFEST_FILE"
        if (( exit_status == 0 )); then
            cp -- "$STATE_FILE" "$LATEST_STATE"
        fi
        supervisor_log info checkpoint_digest \
            "height=$target bytes=$checkpoint_size sha256=$checkpoint_sha256"
        supervisor_log info milestone_manifest_written \
            "height=$target path=$(printf '%q' "$MANIFEST_FILE")"
        if (( exit_status == 0 )); then
            echo "completed_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG_FILE"
        else
            echo "failed_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) exit_status=$exit_status reason=reference_mismatch" >> "$LOG_FILE"
        fi
    else
        echo "failed_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) exit_status=$exit_status" >> "$LOG_FILE"
    fi

    echo
    cat "$RESULT_FILE"
    exit "$exit_status"
}

show_status()
{
    require_command tmux
    local target
    target=$(read_target)
    if [[ -z "$target" ]]; then
        echo "session=$SESSION_NAME state=not_started"
        [[ -s "$LATEST_STATE" ]] && jq '{height, block_hash, num_leaves}' "$LATEST_STATE"
        [[ -s "$CHECKPOINT" ]] && ls -lh "$CHECKPOINT"
        df -h "$RUN_DIR" | tail -1
        exit 0
    fi
    paths_for_target "$target"

    if tmux has-session -t "=$SESSION_NAME" 2>/dev/null; then
        echo "session=$SESSION_NAME state=running target=$target"
    else
        echo "session=$SESSION_NAME state=stopped target=$target"
    fi

    if [[ -s "$LOG_FILE" ]]; then
        local progress
        progress=$(rg '(event=checkpoint_loaded|event=sync_progress|event=checkpoint_saved|event=sync_failed|^(Loaded checkpoint|height=|Saved checkpoint|Sync failed))' "$LOG_FILE" | tail -1 || true)
        [[ -n "$progress" ]] && echo "progress=$progress"
    fi
    if [[ -s "$RESOURCE_FILE" ]]; then
        local sample
        sample=$(tail -1 "$RESOURCE_FILE")
        if [[ "$sample" != timestamp_utc* ]]; then
            local resource_columns
            resource_columns=$(awk -F '\t' 'NR == 1 {print NF}' "$RESOURCE_FILE")
            if (( resource_columns >= 15 )); then
                local sidecar_hwm sidecar_pss pswpin pswpout
                IFS=$'\t' read -r sampled_at sidecar_rss sidecar_hwm sidecar_pss core_rss mem_available swap_free pswpin pswpout _ <<< "$sample"
                core_rss=$(core_rss_kib)
                echo "sampled_at=$sampled_at"
                awk -v s="$sidecar_rss" -v h="$sidecar_hwm" -v p="$sidecar_pss" -v c="$core_rss" -v m="$mem_available" -v w="$swap_free" -v i="$pswpin" -v o="$pswpout" \
                    'BEGIN {printf "sidecar_rss=%.2f_GiB sidecar_hwm=%.2f_GiB sidecar_pss=%.2f_GiB core_rss=%.2f_GiB mem_available=%.2f_GiB swap_free=%.2f_GiB pswpin_pages=%s pswpout_pages=%s\n", s/1048576, h/1048576, p/1048576, c/1048576, m/1048576, w/1048576, i, o}'
            else
                IFS=$'\t' read -r sampled_at sidecar_rss core_rss mem_available swap_free <<< "$sample"
                core_rss=$(core_rss_kib)
                echo "sampled_at=$sampled_at"
                awk -v s="$sidecar_rss" -v c="$core_rss" -v m="$mem_available" -v w="$swap_free" \
                    'BEGIN {printf "sidecar_rss=%.2f_GiB core_rss=%.2f_GiB mem_available=%.2f_GiB swap_free=%.2f_GiB\n", s/1048576, c/1048576, m/1048576, w/1048576}'
            fi
        fi
    fi
    [[ -s "$RESULT_FILE" ]] && cat "$RESULT_FILE"
    [[ -s "$LATEST_STATE" ]] && jq '{height, block_hash, num_leaves}' "$LATEST_STATE"
    df -h "$RUN_DIR" | tail -1
}

follow_log()
{
    local target
    target=$(read_target)
    if [[ -z "$target" ]]; then
        echo "Error: no current run" >&2
        exit 1
    fi
    paths_for_target "$target"
    touch "$LOG_FILE"
    exec tail -n 40 -F "$LOG_FILE"
}

attach_session()
{
    require_command tmux
    if ! tmux has-session -t "=$SESSION_NAME" 2>/dev/null; then
        echo "Error: tmux session is not running: $SESSION_NAME" >&2
        exit 1
    fi
    exec tmux attach-session -t "=$SESSION_NAME"
}

case ${1:-help} in
    start) start_sync "${2:-}" ;;
    rebuild-validate) exec "$SCRIPT_DIR/mainnet-rebuild-validate.sh" start "${2:-}" ;;
    rebuild-status) exec "$SCRIPT_DIR/mainnet-rebuild-validate.sh" status ;;
    rebuild-follow) exec "$SCRIPT_DIR/mainnet-rebuild-validate.sh" follow ;;
    rebuild-attach) exec "$SCRIPT_DIR/mainnet-rebuild-validate.sh" attach ;;
    rebuild-handoff-binary) exec "$SCRIPT_DIR/mainnet-binary-handoff.sh" start "${2:-}" ;;
    run) run_sync "${2:-}" ;;
    status) show_status ;;
    follow) follow_log ;;
    attach) attach_session ;;
    init) initialize_checkpoint "${2:-}" "${3:-}" ;;
    help|-h|--help) usage ;;
    *) echo "Error: unknown command: $1" >&2; usage >&2; exit 1 ;;
esac
