#!/bin/sh
set -eu

if [ "${PLATFORM_NAME:-}" != "macosx" ]; then
    exit 0
fi

frameworks_dir="${TARGET_BUILD_DIR}/${FRAMEWORKS_FOLDER_PATH}"

normalize_framework() {
    name="$1"
    framework="${frameworks_dir}/${name}.framework"

    if [ ! -d "$framework" ] || [ -d "$framework/Versions" ]; then
        return 0
    fi

    tmp="$(mktemp -d "${TMPDIR:-/tmp}/${name}.framework.XXXXXX")"
    normalized="${tmp}/${name}.framework"
    version_dir="${normalized}/Versions/A"

    mkdir -p "$version_dir"

    if [ -f "$framework/$name" ]; then
        mv "$framework/$name" "$version_dir/$name"
    fi

    if [ -f "$framework/Info.plist" ]; then
        mkdir -p "$version_dir/Resources"
        mv "$framework/Info.plist" "$version_dir/Resources/Info.plist"
    fi

    for folder in Headers Modules Resources; do
        if [ -e "$framework/$folder" ]; then
            rm -rf "$version_dir/$folder"
            mv "$framework/$folder" "$version_dir/$folder"
        fi
    done

    find "$framework" -mindepth 1 -maxdepth 1 -exec mv {} "$version_dir/" \;

    ln -s A "$normalized/Versions/Current"
    ln -s Versions/Current/"$name" "$normalized/$name"

    for folder in Headers Modules Resources; do
        if [ -e "$version_dir/$folder" ]; then
            ln -s Versions/Current/"$folder" "$normalized/$folder"
        fi
    done

    rm -rf "$framework"
    mv "$normalized" "$framework"
    rmdir "$tmp"
}

normalize_framework libssl
normalize_framework libghostty
