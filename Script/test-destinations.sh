#!/usr/bin/env bash
set -euo pipefail

swift test

if command -v xcodebuild >/dev/null 2>&1; then
  xcodebuild -scheme SSHKit-Package -destination 'platform=macOS' test
  xcodebuild -scheme SSHKit -destination 'generic/platform=iOS' build
  xcodebuild -scheme SSHKit -destination 'generic/platform=macOS,variant=Mac Catalyst' build
  xcodebuild -scheme SSHKit -destination 'generic/platform=tvOS' build
  xcodebuild -scheme SSHKit -destination 'generic/platform=visionOS' build
fi
