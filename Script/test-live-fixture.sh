#!/usr/bin/env bash
set -euo pipefail

required_variables=(
  SSHKIT_RUN_LIVE_TESTS
  SSHKIT_LIVE_HOST
  SSHKIT_LIVE_PORT
  SSHKIT_LIVE_USERNAME
  SSHKIT_LIVE_PASSWORD
  SSHKIT_LIVE_KNOWN_HOSTS
  SSHKIT_LIVE_PRIVATE_KEY
)

missing_variables=()
for variable in "${required_variables[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    missing_variables+=("$variable")
  fi
done

if [[ -n "${SSHKIT_RUN_LIVE_TESTS:-}" && "${SSHKIT_RUN_LIVE_TESTS}" != "1" ]]; then
  missing_variables+=("SSHKIT_RUN_LIVE_TESTS=1")
fi

if (( ${#missing_variables[@]} > 0 )); then
  printf 'Missing required external live SSH fixture environment:\n' >&2
  printf '  %s\n' "${missing_variables[@]}" >&2
  exit 64
fi

fixture_host="$(printf '%s' "${SSHKIT_LIVE_HOST}" | tr '[:upper:]' '[:lower:]')"
fixture_host="${fixture_host#[}"
fixture_host="${fixture_host%]}"

case "${fixture_host}" in
  localhost|ip6-localhost|127.*|::1|0:0:0:0:0:0:0:1|::ffff:127.*|0.0.0.0)
    printf 'SSHKIT_LIVE_HOST must point at the external fixture host: %s\n' "${SSHKIT_LIVE_HOST}" >&2
    exit 64
    ;;
esac

swift test --filter LiveSSHTests
