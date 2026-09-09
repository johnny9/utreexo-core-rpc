#!/usr/bin/env bash
set -euo pipefail

if (($# == 0)); then
    echo "Usage: $0 PACKAGE..." >&2
    exit 1
fi

# All CI apt dependencies come from Ubuntu. Hosted runners also configure
# unrelated vendor feeds; a Chrome index hash mismatch must not block Boost,
# Clang-Tidy, or Valgrind. Scope both commands without modifying runner sources.
ubuntu_sources=/etc/apt/sources.list.d/ubuntu.sources
if [[ ! -r "$ubuntu_sources" ]]; then
    echo "Missing Ubuntu runner package sources: $ubuntu_sources" >&2
    exit 1
fi
apt_options=(
    -o "Dir::Etc::sourcelist=$ubuntu_sources"
    -o "Dir::Etc::sourceparts=-"
    -o "APT::Update::Error-Mode=any"
    -o "Acquire::Retries=3"
)
sudo apt-get "${apt_options[@]}" update
sudo apt-get "${apt_options[@]}" install --yes --no-install-recommends "$@"
