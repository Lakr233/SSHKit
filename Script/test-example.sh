#!/bin/sh
set -eu

# Run the SSHKit example app's unit + UI tests against macOS, iOS Simulator
# (iOS 26 only), and Mac Catalyst.
#
# macOS / Catalyst use real ad-hoc signing (`CODE_SIGN_IDENTITY = -`,
# `CODE_SIGNING_ALLOWED = YES`) so the App Sandbox + network + user-selected
# file entitlements actually load. iOS Simulator does not enforce
# entitlements, so unsigned is fine.

REPO_ROOT="$(cd "$(dirname "$0")"/.. && pwd)"
PROJECT="$REPO_ROOT/Example/SSHKitExample.xcodeproj"
SCHEME="SSHKitExample"

if [ ! -d "$PROJECT" ]; then
    echo "ERROR: $PROJECT not found." >&2
    exit 1
fi

ADHOC_FLAGS="CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES DEVELOPMENT_TEAM="
SIM_FLAGS="CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO DEVELOPMENT_TEAM="

run_macos() {
    echo "==> macOS"
    # shellcheck disable=SC2086
    xcodebuild test \
        -project "$PROJECT" \
        -scheme "$SCHEME" \
        -destination 'platform=macOS' \
        $ADHOC_FLAGS
}

run_catalyst() {
    echo "==> Mac Catalyst"
    # shellcheck disable=SC2086
    xcodebuild test \
        -project "$PROJECT" \
        -scheme "$SCHEME" \
        -destination 'platform=macOS,variant=Mac Catalyst' \
        $ADHOC_FLAGS
}

run_ios_simulator() {
    echo "==> iOS Simulator (iOS 26)"
    if ! command -v jq >/dev/null 2>&1; then
        echo "ERROR: jq is required (brew install jq)." >&2
        exit 1
    fi
    UDID=$(xcrun simctl list devices available --json | jq -r '
        .devices
        | to_entries
        | map(select(.key | test("SimRuntime\\.iOS-26-")))
        | map(.value[])
        | flatten
        | map(select(.isAvailable))
        | (first // empty)
        | .udid')
    if [ -z "${UDID:-}" ]; then
        echo "ERROR: No iOS 26 simulator available." >&2
        echo "       Install one via Xcode or 'xcodebuild -downloadPlatform iOS'." >&2
        exit 1
    fi
    echo "Using iOS 26 simulator UDID: $UDID"
    # shellcheck disable=SC2086
    xcodebuild test \
        -project "$PROJECT" \
        -scheme "$SCHEME" \
        -destination "platform=iOS Simulator,id=$UDID" \
        $SIM_FLAGS
}

# Allow callers to restrict destinations: `Script/test-example.sh macos catalyst`
if [ "$#" -gt 0 ]; then
    for arg in "$@"; do
        case "$arg" in
            macos) run_macos ;;
            catalyst) run_catalyst ;;
            ios) run_ios_simulator ;;
            *) echo "Unknown destination: $arg"; exit 1 ;;
        esac
    done
else
    run_macos
    run_ios_simulator
    run_catalyst
fi
