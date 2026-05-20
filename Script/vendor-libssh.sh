#!/bin/zsh
set -euo pipefail

version="${1:-0.12.0}"
archive="libssh-${version}.tar.xz"
release_dir="${version%.*}"
url="https://www.libssh.org/files/${release_dir}/${archive}"
root="$(cd "$(dirname "$0")/.." && pwd)"
workdir="$(mktemp -d)"

trap 'rm -rf "$workdir"' EXIT

echo "[+] downloading libssh ${version}"
curl -L "$url" -o "$workdir/$archive"

echo "[+] extracting source"
tar -xf "$workdir/$archive" -C "$workdir"

rm -rf "$root/Vendor/libssh"
mkdir -p "$root/Vendor/libssh"
cp -R "$workdir/libssh-${version}/include" "$root/Vendor/libssh/include"
cp -R "$workdir/libssh-${version}/src" "$root/Vendor/libssh/src"
cp "$workdir/libssh-${version}/COPYING" "$root/Vendor/libssh/COPYING"
cp "$workdir/libssh-${version}/AUTHORS" "$root/Vendor/libssh/AUTHORS"

echo "[+] vendored libssh ${version}"
