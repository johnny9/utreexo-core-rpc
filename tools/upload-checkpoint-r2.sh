#!/usr/bin/env bash
# Upload the pinned mainnet checkpoint to an existing Cloudflare R2 bucket.
# Credentials are accepted through the environment or a silent terminal prompt and
# are passed to rclone through its environment-only remote configuration.
set -euo pipefail
set +x

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WORKSPACE_DIR=$(cd -- "$SCRIPT_DIR/../.." && pwd)

CHECKPOINT="$WORKSPACE_DIR/artifacts/mainnet-tip/mainnet-943013-compact.chk"
MANIFEST="$WORKSPACE_DIR/sidecar/contrib/checkpoints/mainnet-943013.json"
OBJECT_KEY=mainnet-943013-compact.chk
MANIFEST_KEY=mainnet-943013.json
EXPECTED_SIZE=14893913136
EXPECTED_SHA256=e869cb2eaf6a42d71010464b1dac7d0cd5cc7ed237ba78d2c653d2c8efa5a492
RCLONE_BIN=${RCLONE_BIN:-}
ACCOUNT_ID=${R2_ACCOUNT_ID:-}
BUCKET=${R2_BUCKET:-}
ACCESS_KEY_ID=${R2_ACCESS_KEY_ID:-}
SECRET_ACCESS_KEY=${R2_SECRET_ACCESS_KEY:-}

usage()
{
    cat <<'EOF'
Usage: upload-checkpoint-r2.sh [options]

Uploads the validated height-943013 checkpoint and its JSON manifest to an
existing Cloudflare R2 bucket. Existing remote objects are not overwritten.

Options:
  --account-id ID       Cloudflare account ID (or set R2_ACCOUNT_ID)
  --bucket NAME         Existing R2 bucket name (or set R2_BUCKET)
  --object-key KEY      Checkpoint object key (default: mainnet-943013-compact.chk)
  --manifest-key KEY    Manifest object key (default: mainnet-943013.json)
  --rclone PATH         rclone executable (or set RCLONE_BIN)
  -h, --help            Show this help

Credentials may be set as R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY. If either
is absent, an interactive terminal prompt reads it without echoing the secret.
EOF
}

die()
{
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --account-id)
            (($# >= 2)) || die "--account-id requires a value"
            ACCOUNT_ID=$2
            shift 2
            ;;
        --bucket)
            (($# >= 2)) || die "--bucket requires a value"
            BUCKET=$2
            shift 2
            ;;
        --object-key)
            (($# >= 2)) || die "--object-key requires a value"
            OBJECT_KEY=$2
            shift 2
            ;;
        --manifest-key)
            (($# >= 2)) || die "--manifest-key requires a value"
            MANIFEST_KEY=$2
            shift 2
            ;;
        --rclone)
            (($# >= 2)) || die "--rclone requires a value"
            RCLONE_BIN=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) die "unknown option: $1" ;;
    esac
done

if [[ -z "$RCLONE_BIN" ]]; then
    RCLONE_BIN=$(command -v rclone || true)
fi
[[ -n "$RCLONE_BIN" && -x "$RCLONE_BIN" ]] ||
    die "rclone is not installed; set RCLONE_BIN to an executable rclone path"
[[ -f "$CHECKPOINT" ]] || die "checkpoint not found: $CHECKPOINT"
[[ -f "$MANIFEST" ]] || die "manifest not found: $MANIFEST"

if [[ -z "$ACCOUNT_ID" ]]; then
    [[ -t 0 ]] || die "set R2_ACCOUNT_ID or use --account-id"
    read -r -p 'Cloudflare account ID: ' ACCOUNT_ID
fi
if [[ -z "$BUCKET" ]]; then
    [[ -t 0 ]] || die "set R2_BUCKET or use --bucket"
    read -r -p 'Existing R2 bucket name: ' BUCKET
fi
if [[ -z "$ACCESS_KEY_ID" ]]; then
    [[ -t 0 ]] || die "set R2_ACCESS_KEY_ID or run from an interactive terminal"
    read -r -p 'R2 access key ID: ' ACCESS_KEY_ID
fi
if [[ -z "$SECRET_ACCESS_KEY" ]]; then
    [[ -t 0 ]] || die "set R2_SECRET_ACCESS_KEY or run from an interactive terminal"
    read -r -s -p 'R2 secret access key: ' SECRET_ACCESS_KEY
    printf '\n'
fi

[[ "$ACCOUNT_ID" =~ ^[[:xdigit:]]{32}$ ]] || die "account ID must be 32 hexadecimal characters"
[[ "$BUCKET" =~ ^[a-z0-9][a-z0-9.-]*[a-z0-9]$ ]] || die "invalid R2 bucket name"
[[ "$OBJECT_KEY" != /* && "$OBJECT_KEY" != *..* ]] || die "unsafe checkpoint object key"
[[ "$MANIFEST_KEY" != /* && "$MANIFEST_KEY" != *..* ]] || die "unsafe manifest object key"
[[ -n "$ACCESS_KEY_ID" && -n "$SECRET_ACCESS_KEY" ]] || die "R2 credentials cannot be empty"

actual_size=$(stat -c '%s' -- "$CHECKPOINT")
[[ "$actual_size" == "$EXPECTED_SIZE" ]] ||
    die "checkpoint size mismatch: expected $EXPECTED_SIZE, got $actual_size"

printf 'Verifying local checkpoint SHA-256 (this takes about 40 seconds)...\n'
actual_sha256=$(sha256sum -- "$CHECKPOINT")
actual_sha256=${actual_sha256%% *}
[[ "$actual_sha256" == "$EXPECTED_SHA256" ]] ||
    die "checkpoint SHA-256 mismatch: expected $EXPECTED_SHA256, got $actual_sha256"

export RCLONE_CONFIG_R2_TYPE=s3
export RCLONE_CONFIG_R2_PROVIDER=Cloudflare
export RCLONE_CONFIG_R2_ACCESS_KEY_ID=$ACCESS_KEY_ID
export RCLONE_CONFIG_R2_SECRET_ACCESS_KEY=$SECRET_ACCESS_KEY
export RCLONE_CONFIG_R2_ENDPOINT="https://$ACCOUNT_ID.r2.cloudflarestorage.com"
trap 'unset ACCESS_KEY_ID SECRET_ACCESS_KEY RCLONE_CONFIG_R2_ACCESS_KEY_ID RCLONE_CONFIG_R2_SECRET_ACCESS_KEY' EXIT

printf 'Checking access to R2 bucket %s...\n' "$BUCKET"
"$RCLONE_BIN" lsf "r2:$BUCKET" --max-depth 1 >/dev/null

printf 'Uploading %s bytes to r2:%s/%s...\n' "$EXPECTED_SIZE" "$BUCKET" "$OBJECT_KEY"
"$RCLONE_BIN" copyto "$CHECKPOINT" "r2:$BUCKET/$OBJECT_KEY" \
    --immutable \
    --s3-no-check-bucket \
    --s3-upload-cutoff 200Mi \
    --s3-chunk-size 128Mi \
    --s3-upload-concurrency 4 \
    --metadata \
    --metadata-set "sha256=$EXPECTED_SHA256" \
    --metadata-set "checkpoint-height=943013" \
    --metadata-set "checkpoint-format=3" \
    --header-upload 'Cache-Control: public, max-age=31536000, immutable' \
    --retries 10 \
    --low-level-retries 20 \
    --stats 10s \
    --progress

remote_size=$("$RCLONE_BIN" lsl "r2:$BUCKET/$OBJECT_KEY" | awk 'NR == 1 {print $1}')
[[ "$remote_size" == "$EXPECTED_SIZE" ]] ||
    die "remote size mismatch: expected $EXPECTED_SIZE, got ${remote_size:-missing}"

printf 'Uploading checkpoint manifest to r2:%s/%s...\n' "$BUCKET" "$MANIFEST_KEY"
"$RCLONE_BIN" copyto "$MANIFEST" "r2:$BUCKET/$MANIFEST_KEY" \
    --immutable \
    --s3-no-check-bucket \
    --header-upload 'Cache-Control: public, max-age=300' \
    --retries 10 \
    --low-level-retries 20

printf 'Upload complete.\n'
printf 'Checkpoint: r2:%s/%s\n' "$BUCKET" "$OBJECT_KEY"
printf 'Manifest:   r2:%s/%s\n' "$BUCKET" "$MANIFEST_KEY"
printf 'SHA-256:    %s\n' "$EXPECTED_SHA256"
