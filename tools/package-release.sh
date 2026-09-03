#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-${root_dir}/build-release-package}"

python3 "${root_dir}/tools/verify-checkpoint-manifest.py"
cmake -S "${root_dir}" -B "${build_dir}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DUTREEXO_WARNINGS_AS_ERRORS=ON
cmake --build "${build_dir}" --parallel "${UTREEXO_BUILD_JOBS:-2}"
ctest --test-dir "${build_dir}" --output-on-failure
cmake --build "${build_dir}" --target package

archives=("${build_dir}"/utreexo-bridge-*.tar.gz)
[[ ${#archives[@]} -eq 1 && -f "${archives[0]}" ]] || {
  printf 'Expected exactly one release archive in %s\n' "${build_dir}" >&2
  exit 1
}

# CPack's archive generator otherwise preserves the build account's numeric
# ownership and umask-derived modes. Repack the trusted, just-generated tree so
# extracting as root cannot transfer runner ownership or group-writable modes
# onto an installation prefix.
archive=${archives[0]}
archive_dir=$(dirname "${archive}")
archive_name=$(basename "${archive}")
staging_dir=$(mktemp -d "${build_dir}/package-normalize.XXXXXX")
normalized_archive="${archive}.normalized"
cleanup()
{
  rm -rf -- "${staging_dir}"
  rm -f -- "${normalized_archive}"
}
trap cleanup EXIT

tar -xzf "${archive}" -C "${staging_dir}"
top_level=("${staging_dir}"/*)
[[ ${#top_level[@]} -eq 1 && -d "${top_level[0]}" ]] || {
  printf 'Release archive must contain exactly one top-level directory\n' >&2
  exit 1
}
top_level_name=$(basename "${top_level[0]}")
tar --sort=name --owner=0 --group=0 --numeric-owner --mode='go-w' \
  -czf "${normalized_archive}" -C "${staging_dir}" "${top_level_name}"
mv -- "${normalized_archive}" "${archive}"

(
  cd "${archive_dir}"
  sha256sum "${archive_name}" > "${archive_name}.sha256"
)
printf 'Created %s\n' "${archive}"
printf 'Created %s\n' "${archive}.sha256"
