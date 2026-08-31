#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SIDECAR_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE_DIR=$(cd -- "$SIDECAR_DIR/.." && pwd)

SESSION_NAME=${UTREEXO_REBUILD_TMUX_SESSION:-utreexo-mainnet-v3}
HANDOFF_SESSION=${UTREEXO_BINARY_HANDOFF_TMUX_SESSION:-$SESSION_NAME-binary-handoff}
RUN_DIR=${UTREEXO_REBUILD_RUN_DIR:-$WORKSPACE_DIR/artifacts/mainnet-validation-v3}
CONTROLLER=$SCRIPT_DIR/mainnet-rebuild-validate.sh
PIPELINE_STATUS=$RUN_DIR/pipeline-status.json
PIPELINE_LOG=$RUN_DIR/pipeline.log
PIPELINE_LOCK=$RUN_DIR/pipeline.lock
BINARY_DIGEST=$RUN_DIR/sidecar-binary.sha256
BINARY_PATH_FILE=$RUN_DIR/sidecar-binary.path
BINARY_TRANSITIONS=$RUN_DIR/sidecar-binary-transitions.json
PINNED_REFERENCE=$RUN_DIR/reference-state.json
HANDOFF_LOG=$RUN_DIR/binary-handoff.log

die()
{
    echo "Error: $*" >&2
    exit 1
}

commit_handoff()
{
    exec 9> "$PIPELINE_LOCK"
    flock -w 30 9 || die "could not acquire the rebuild pipeline lock"

    local transitions='{"format":1,"transitions":[]}'
    if [[ -s "$BINARY_TRANSITIONS" ]]; then
        transitions=$(jq -c . "$BINARY_TRANSITIONS")
    fi
    jq -n \
        --argjson history "$transitions" \
        --arg adopted_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg reason "$HANDOFF_REASON" \
        --arg old_binary_sha256 "$OLD_SHA" \
        --arg old_sidecar_version "$OLD_VERSION" \
        --arg new_binary_sha256 "$NEW_SHA" \
        --arg new_sidecar_version "$NEW_VERSION" \
        --arg new_binary "$NEW_BINARY" \
        --arg checkpoint "$CHECKPOINT" \
        --arg checkpoint_sha256 "$RECORDED_CHECKPOINT_SHA" \
        --argjson checkpoint_height "$STAGE_TARGET" \
        --slurpfile checkpoint_state "$STATE" \
        '$history | .transitions += [{adopted_at_utc: $adopted_at_utc, reason: $reason,
          checkpoint_height: $checkpoint_height, checkpoint: $checkpoint,
          checkpoint_sha256: $checkpoint_sha256,
          checkpoint_state: ($checkpoint_state[0] | {height, block_hash, num_leaves, roots}),
          old_binary_sha256: $old_binary_sha256, old_sidecar_version: $old_sidecar_version,
          new_binary_sha256: $new_binary_sha256, new_sidecar_version: $new_sidecar_version,
          new_binary: $new_binary}]' > "$BINARY_TRANSITIONS.tmp.$$"
    printf '%s\n' "$NEW_SHA" > "$BINARY_DIGEST.tmp.$$"
    printf '%s\n' "$NEW_BINARY" > "$BINARY_PATH_FILE.tmp.$$"
    mv -- "$BINARY_TRANSITIONS.tmp.$$" "$BINARY_TRANSITIONS"
    mv -- "$BINARY_DIGEST.tmp.$$" "$BINARY_DIGEST"
    mv -- "$BINARY_PATH_FILE.tmp.$$" "$BINARY_PATH_FILE"
    printf 'timestamp=%s level=info event=binary_handoff_completed checkpoint_height=%s old_sha256=%s new_sha256=%s new_binary=%q reason=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$STAGE_TARGET" "$OLD_SHA" "$NEW_SHA" \
        "$NEW_BINARY" "$HANDOFF_REASON" >> "$PIPELINE_LOG"
    flock -u 9

    env \
        "${RESTART_ENV[@]}" \
        UTREEXO_REBUILD_TMUX_SESSION="$SESSION_NAME" \
        UTREEXO_REBUILD_RUN_DIR="$RUN_DIR" \
        UTREEXO_BINARY="$NEW_BINARY" \
        "$CONTROLLER" start "$PIPELINE_TARGET"

    echo "Binary handoff completed at height $STAGE_TARGET: $NEW_VERSION"
}

for command in tmux jq sha256sum flock rg realpath ps tail; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

RECOVERY_MODE=0
case ${1:-} in
    start)
        NEW_BINARY=${2:-}
        [[ -n "$NEW_BINARY" && -x "$NEW_BINARY" ]] ||
            die "handoff requires an executable sidecar path"
        NEW_BINARY=$(realpath -- "$NEW_BINARY")
        mkdir -p -- "$RUN_DIR"
        tmux has-session -t "=$HANDOFF_SESSION" 2>/dev/null &&
            die "binary handoff is already scheduled: $HANDOFF_SESSION"
        printf -v HANDOFF_COMMAND 'exec %q internal-run %q >> %q 2>&1' \
            "$SCRIPT_DIR/mainnet-binary-handoff.sh" "$NEW_BINARY" "$HANDOFF_LOG"
        tmux new-session -d -s "$HANDOFF_SESSION" -c "$WORKSPACE_DIR" \
            -e "UTREEXO_REBUILD_TMUX_SESSION=$SESSION_NAME" \
            -e "UTREEXO_BINARY_HANDOFF_TMUX_SESSION=$HANDOFF_SESSION" \
            -e "UTREEXO_REBUILD_RUN_DIR=$RUN_DIR" \
            "$HANDOFF_COMMAND"
        echo "Scheduled binary handoff session: $HANDOFF_SESSION"
        echo "New binary: $NEW_BINARY"
        echo "The active stage will finish and be verified before the controller restarts."
        echo "Handoff log: $HANDOFF_LOG"
        exit 0
        ;;
    internal-run) NEW_BINARY=${2:-} ;;
    resume-completed)
        NEW_BINARY=${2:-}
        RECOVERY_MODE=1
        ;;
    *) die "usage: $(basename "$0") start PATH | resume-completed PATH" ;;
esac

[[ -n "$NEW_BINARY" && -x "$NEW_BINARY" ]] || die "handoff requires an executable sidecar path"
NEW_BINARY=$(realpath -- "$NEW_BINARY")
NEW_VERSION=$("$NEW_BINARY" --version)
[[ "$NEW_VERSION" == *"checkpoint_format=3 forest_format=1"* ]] ||
    die "new sidecar has an incompatible checkpoint or forest format: $NEW_VERSION"
NEW_SHA=$(sha256sum -- "$NEW_BINARY" | awk '{print $1}')

if (( RECOVERY_MODE != 0 )); then
    [[ -s "$BINARY_DIGEST" && -s "$PINNED_REFERENCE" && -s "$RUN_DIR/latest-state.json" ]] ||
        die "the rebuild pipeline has no completed resumable state"
    tmux has-session -t "=$SESSION_NAME" 2>/dev/null &&
        die "cannot recover a handoff while the rebuild controller is running"
    STAGE_TARGET=$(jq -r '.height' "$RUN_DIR/latest-state.json")
    PIPELINE_TARGET=$(jq -r '.height' "$PINNED_REFERENCE")
    [[ "$STAGE_TARGET" =~ ^[0-9]+$ && "$PIPELINE_TARGET" =~ ^[0-9]+$ ]] ||
        die "pipeline state contains a non-numeric height"
    RESULT=$RUN_DIR/result-$STAGE_TARGET.txt
    STATE=$RUN_DIR/state-$STAGE_TARGET.json
    MANIFEST=$RUN_DIR/manifest-$STAGE_TARGET.json
    [[ -s "$RESULT" && -s "$STATE" && -s "$MANIFEST" ]] ||
        die "completed stage artifacts are missing at height $STAGE_TARGET"
    [[ $(awk -F= '$1 == "exit_status" {print $2}' "$RESULT") == 0 ]] ||
        die "the last completed stage did not exit successfully"
    jq -e --argjson height "$STAGE_TARGET" '.height == $height' "$STATE" >/dev/null ||
        die "completed state height does not match latest-state.json"
    jq -e --argjson height "$STAGE_TARGET" '.height == $height' "$MANIFEST" >/dev/null ||
        die "completed manifest height does not match latest-state.json"
    CHECKPOINT=$(jq -r '.checkpoint' "$MANIFEST")
    RECORDED_CHECKPOINT_SHA=$(jq -r '.checkpoint_sha256' "$MANIFEST")
    [[ -f "$CHECKPOINT" && "$RECORDED_CHECKPOINT_SHA" =~ ^[0-9a-f]{64}$ ]] ||
        die "completed stage checkpoint or digest is invalid"
    [[ $(sha256sum -- "$CHECKPOINT" | awk '{print $1}') == "$RECORDED_CHECKPOINT_SHA" ]] ||
        die "completed stage checkpoint does not match its manifest"
    [[ $(< "$BINARY_DIGEST") == "$NEW_SHA" ]] ||
        die "the pending binary digest does not match the requested executable"
    OLD_SHA_FIELD=$(rg -o 'old_sha256=[0-9a-f]{64}' "$PIPELINE_LOG" | tail -n 1)
    OLD_SHA=${OLD_SHA_FIELD#*=}
    [[ "$OLD_SHA" =~ ^[0-9a-f]{64}$ && "$OLD_SHA" != "$NEW_SHA" ]] ||
        die "could not recover the prior binary digest from the handoff audit log"
    OLD_VERSION=$(jq -r '.sidecar_version' "$MANIFEST")
    RESTART_ENV=()
    for variable in \
        UTREEXO_REBUILD_REFERENCE_STATE \
        UTREEXO_REBUILD_LOG_LEVEL \
        UTREEXO_REBUILD_MAX_ATTEMPTS \
        UTREEXO_REBUILD_RETRY_DELAY_SECONDS \
        UTREEXO_REBUILD_MIN_FREE_GIB \
        UTREEXO_COMPACTOR \
        UTREEXO_BITCOIN_CLI \
        UTREEXO_RPC_COOKIE \
        UTREEXO_CORE_PID_FILE \
        UTREEXO_CHECKPOINT_SHA256; do
        if [[ -v $variable ]]; then RESTART_ENV+=("$variable=${!variable}"); fi
    done
    HANDOFF_REASON=checkpoint_boundary_optimization_handoff_recovery
    commit_handoff
    exit 0
fi

[[ -s "$PIPELINE_STATUS" && -s "$BINARY_DIGEST" && -s "$PINNED_REFERENCE" ]] ||
    die "the rebuild pipeline has no resumable pinned state"
tmux has-session -t "=$SESSION_NAME" 2>/dev/null ||
    die "rebuild session is not running: $SESSION_NAME"

STAGE=$(jq -r '.stage' "$PIPELINE_STATUS")
STAGE_TARGET=$(jq -r '.target_height' "$PIPELINE_STATUS")
PIPELINE_TARGET=$(jq -r '.height' "$PINNED_REFERENCE")
CHECKPOINT=$(jq -r '.checkpoint' "$PIPELINE_STATUS")
[[ $(jq -r '.state' "$PIPELINE_STATUS") == running && "$STAGE" == "sync-$STAGE_TARGET" ]] ||
    die "binary handoff requires an active sync stage"
[[ "$STAGE_TARGET" =~ ^[0-9]+$ && "$PIPELINE_TARGET" =~ ^[0-9]+$ ]] ||
    die "pipeline status contains a non-numeric target"
[[ -n "$CHECKPOINT" ]] || die "pipeline status has no active checkpoint path"

CONTROLLER_PID=$(tmux display-message -p -t "=$SESSION_NAME:0.0" '#{pane_pid}')
[[ "$CONTROLLER_PID" =~ ^[0-9]+$ ]] || die "could not identify the rebuild controller"
CONTROLLER_ARGS=$(ps -o args= -p "$CONTROLLER_PID")
rg -F -q 'mainnet-rebuild-validate.sh internal-run' <<< "$CONTROLLER_ARGS" ||
    die "tmux pane does not contain the expected rebuild controller"

# Preserve the controller's explicit run configuration across the new tmux
# session. The binary itself is deliberately replaced below.
RESTART_ENV=()
for variable in \
    UTREEXO_REBUILD_REFERENCE_STATE \
    UTREEXO_REBUILD_LOG_LEVEL \
    UTREEXO_REBUILD_MAX_ATTEMPTS \
    UTREEXO_REBUILD_RETRY_DELAY_SECONDS \
    UTREEXO_REBUILD_MIN_FREE_GIB \
    UTREEXO_COMPACTOR \
    UTREEXO_BITCOIN_CLI \
    UTREEXO_RPC_COOKIE \
    UTREEXO_CORE_PID_FILE \
    UTREEXO_CHECKPOINT_SHA256; do
    assignment=$(tmux show-environment -t "=$SESSION_NAME" "$variable" 2>/dev/null || true)
    if [[ "$assignment" == "$variable="* ]]; then
        RESTART_ENV+=("$assignment")
    fi
done

[[ -s "$RUN_DIR/sidecar.pid" ]] || die "active stage has no sidecar pid file"
read -r SIDECAR_PID < "$RUN_DIR/sidecar.pid"
[[ "$SIDECAR_PID" =~ ^[0-9]+$ ]] || die "sidecar pid file is invalid"
kill -0 "$SIDECAR_PID" 2>/dev/null || die "active stage sidecar is no longer running"

OLD_SHA=$(< "$BINARY_DIGEST")
[[ "$OLD_SHA" =~ ^[0-9a-f]{64}$ ]] || die "pinned sidecar digest is invalid"
if [[ "$OLD_SHA" == "$NEW_SHA" ]]; then
    die "new sidecar is already the pinned binary"
fi

printf 'timestamp=%s level=info event=binary_handoff_scheduled stage=%s old_sha256=%s new_sha256=%s new_binary=%q\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$STAGE" "$OLD_SHA" "$NEW_SHA" "$NEW_BINARY" \
    >> "$PIPELINE_LOG"
# Arm the existing stage-boundary digest check. The running executable has its
# old inode mapped and continues unaffected, while the controller cannot start
# another stage with that old executable after this stage exits.
printf '%s\n' "$NEW_SHA" > "$BINARY_DIGEST.handoff.$$"
mv -- "$BINARY_DIGEST.handoff.$$" "$BINARY_DIGEST"
printf 'timestamp=%s level=info event=binary_handoff_guard_armed stage=%s new_sha256=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$STAGE" "$NEW_SHA" >> "$PIPELINE_LOG"

sidecar_is_running()
{
    kill -0 "$SIDECAR_PID" 2>/dev/null || return 1
    ps -o args= -p "$SIDECAR_PID" | rg -F -q -- "--stop-height=$STAGE_TARGET"
}

while sidecar_is_running; do
    sleep 5
done

RESULT=$RUN_DIR/result-$STAGE_TARGET.txt
STATE=$RUN_DIR/state-$STAGE_TARGET.json
MANIFEST=$RUN_DIR/manifest-$STAGE_TARGET.json
for ((attempt = 0; attempt < 60; ++attempt)); do
    [[ -s "$RESULT" ]] && rg -q '^finished_at_utc=' "$RESULT" && break
    sleep 5
done

if [[ ! -s "$RESULT" || $(awk -F= '$1 == "exit_status" {print $2}' "$RESULT") != 0 ]]; then
    printf '%s\n' "$OLD_SHA" > "$BINARY_DIGEST.restore.$$"
    mv -- "$BINARY_DIGEST.restore.$$" "$BINARY_DIGEST"
    printf 'timestamp=%s level=warn event=binary_handoff_deferred stage=%s reason=stage_failed\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$STAGE" >> "$PIPELINE_LOG"
    exit 1
fi

for ((attempt = 0; attempt < 60; ++attempt)); do
    if [[ -s "$STATE" && -s "$MANIFEST" && -s "$RUN_DIR/latest-state.json" ]]; then break; fi
    sleep 5
done
if ! jq -e --argjson height "$STAGE_TARGET" '.height == $height' "$STATE" >/dev/null 2>&1 ||
   ! jq -e --argjson height "$STAGE_TARGET" '.height == $height' "$MANIFEST" >/dev/null 2>&1; then
    die "successful stage did not publish its expected state and manifest"
fi

[[ $(sha256sum -- "$NEW_BINARY" | awk '{print $1}') == "$NEW_SHA" ]] ||
    die "new sidecar changed while waiting for the checkpoint boundary"
RECORDED_CHECKPOINT_SHA=$(jq -r '.checkpoint_sha256' "$MANIFEST")
[[ "$RECORDED_CHECKPOINT_SHA" =~ ^[0-9a-f]{64}$ ]] ||
    die "completed stage manifest has no checkpoint digest"
[[ $(sha256sum -- "$CHECKPOINT" | awk '{print $1}') == "$RECORDED_CHECKPOINT_SHA" ]] ||
    die "completed stage checkpoint does not match its manifest"

OLD_VERSION=$(jq -r '.sidecar_version' "$MANIFEST")
if kill -0 "$CONTROLLER_PID" 2>/dev/null; then
    kill -TERM "$CONTROLLER_PID" 2>/dev/null || true
    kill -CONT "$CONTROLLER_PID" 2>/dev/null || true
fi
for ((attempt = 0; attempt < 30; ++attempt)); do
    tmux has-session -t "=$SESSION_NAME" 2>/dev/null || break
    sleep 1
done
tmux has-session -t "=$SESSION_NAME" 2>/dev/null &&
    die "old rebuild controller did not stop at the checkpoint boundary"

HANDOFF_REASON=checkpoint_boundary_optimization_handoff
commit_handoff
