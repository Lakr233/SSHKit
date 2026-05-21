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
  SSHKIT_LEGACY_RSA_HOST
  SSHKIT_LEGACY_RSA_PORT
  SSHKIT_LEGACY_RSA_USERNAME
  SSHKIT_LEGACY_RSA_PASSWORD
  SSHKIT_LEGACY_RSA_KNOWN_HOSTS
  SSHKIT_DROPBEAR_HOST
  SSHKIT_DROPBEAR_PORT
  SSHKIT_DROPBEAR_USERNAME
  SSHKIT_DROPBEAR_PASSWORD
  SSHKIT_DROPBEAR_KNOWN_HOSTS
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

require_external_fixture_host() {
  local variable_name="$1"
  local host="${!variable_name}"
  local normalized_host
  normalized_host="$(printf '%s' "${host}" | tr '[:upper:]' '[:lower:]')"
  normalized_host="${normalized_host#[}"
  normalized_host="${normalized_host%]}"

  case "${normalized_host}" in
    localhost|ip6-localhost|127.*|::1|0:0:0:0:0:0:0:1|::ffff:127.*|0.0.0.0)
      printf '%s must point at an external fixture host: %s\n' "${variable_name}" "${host}" >&2
      exit 64
      ;;
  esac
}

require_external_fixture_host SSHKIT_LIVE_HOST
require_external_fixture_host SSHKIT_LEGACY_RSA_HOST
require_external_fixture_host SSHKIT_DROPBEAR_HOST

for tool in /usr/bin/ssh-agent /usr/bin/ssh-add; do
  if [[ ! -x "${tool}" ]]; then
    printf 'Missing required local tool for live agent tests: %s\n' "${tool}" >&2
    exit 64
  fi
done

log_live() {
  printf '[live] %s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

test_output="$(mktemp -t sshkit-live-tests.XXXXXX)"
heartbeat_pid=""

stop_heartbeat() {
  if [[ -n "${heartbeat_pid}" ]]; then
    kill "${heartbeat_pid}" 2>/dev/null || true
    wait "${heartbeat_pid}" 2>/dev/null || true
    heartbeat_pid=""
  fi
}

cleanup() {
  stop_heartbeat
  rm -f "${test_output}"
}

trap cleanup EXIT INT TERM

(
  started_at="$(date +%s)"
  while true; do
    sleep 15
    now="$(date +%s)"
    output_bytes="$(wc -c <"${test_output}" 2>/dev/null || printf '0')"
    log_live "still running elapsed=$((now - started_at))s output_bytes=${output_bytes}"
  done
) &
heartbeat_pid="$!"

swift_test_command=(swift test --no-parallel --filter LiveSSHTests)
log_live "starting external live SSH fixture suite command=${swift_test_command[*]}"

set +e
NSUnbufferedIO=YES "${swift_test_command[@]}" 2>&1 | tee "${test_output}"
test_status="${PIPESTATUS[0]}"
set -e

stop_heartbeat

if (( test_status != 0 )); then
  log_live "external live SSH fixture suite failed status=${test_status}"
  exit "${test_status}"
fi

if grep -E "Test Case '.*' skipped|tests skipped|Test \".*\" skipped" "${test_output}" >/dev/null; then
  printf 'Live SSH fixture run completed with skipped tests; all live tests must run against the external fixture hosts.\n' >&2
  exit 65
fi

log_live "external live SSH fixture suite completed with all live tests enabled"
