#!/usr/bin/env bash
set -euo pipefail

version="${1:-$(git describe --tags --always --dirty)}"
artifact_dir="${ARTIFACT_DIR:-.build/release-artifacts}"
archive_prefix="SSHKit-${version}"

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  printf 'Release packaging requires a clean git checkout.\n' >&2
  exit 64
fi

mkdir -p "${artifact_dir}"

swift package resolve
swift build -c release

git archive --format zip --prefix "${archive_prefix}/" --output "${artifact_dir}/${archive_prefix}-source.zip" HEAD
swift package dump-package > "${artifact_dir}/${archive_prefix}-package.json"

(
  cd "${artifact_dir}"
  shasum -a 256 "${archive_prefix}-source.zip" "${archive_prefix}-package.json" > "${archive_prefix}-checksums.txt"
)

printf 'Release artifacts written to %s\n' "${artifact_dir}"
