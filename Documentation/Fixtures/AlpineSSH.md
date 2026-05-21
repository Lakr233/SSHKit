# Alpine SSH Live Fixture

This fixture describes the opt-in live SSH target used by `LiveSSHTests`.

## Required Environment

Set these values before running live tests:

```sh
export SSHKIT_RUN_LIVE_TESTS=1
export SSHKIT_LIVE_HOST="example.com"
export SSHKIT_LIVE_PORT="22"
export SSHKIT_LIVE_USERNAME="root"
export SSHKIT_LIVE_PASSWORD="<password>"
export SSHKIT_LIVE_KNOWN_HOSTS="<known-hosts-entry>"
export SSHKIT_LIVE_PRIVATE_KEY="<private-key-pem>"
export SSHKIT_LIVE_REMOTE_SSHD_PORT="22"
# Optional extra fixtures:
# export SSHKIT_LEGACY_RSA_HOST="legacy-rsa.example.com"
# export SSHKIT_LEGACY_RSA_PORT="22"
# export SSHKIT_LEGACY_RSA_USERNAME="root"
# export SSHKIT_LEGACY_RSA_PASSWORD="<password>"
# export SSHKIT_LEGACY_RSA_KNOWN_HOSTS="<known-hosts-entry>"
# export SSHKIT_DROPBEAR_HOST="dropbear.example.com"
# export SSHKIT_DROPBEAR_PORT="22"
# export SSHKIT_DROPBEAR_USERNAME="root"
# export SSHKIT_DROPBEAR_PASSWORD="<password>"
# export SSHKIT_DROPBEAR_KNOWN_HOSTS="<known-hosts-entry>"
```

Each known-hosts value should contain one or more complete OpenSSH known-hosts lines (one per host-key type). Listing every key type the server advertises (typically `ssh-rsa`, `ecdsa-sha2-nistp256`, `ssh-ed25519`) keeps verification stable across libssh host-key preference changes and across profiles like `legacyRSA`. `SSHKIT_LIVE_PRIVATE_KEY` should contain a private key accepted by the Alpine fixture user. `SSHKIT_LIVE_REMOTE_SSHD_PORT` is optional and defaults to `22`; it is the SSH port visible from inside the fixture host for direct TCP, local forward, and dynamic SOCKS tests. The legacy RSA fixture uses `SSHAlgorithmProfile.legacyRSA`, password authentication, known-host verification, and a real exec channel. The Dropbear fixture uses password authentication, known-host verification, and a real exec channel.

## Current Alpine Container Topology

The current shared Alpine fixture runs OpenSSH in a Docker container and publishes the container's port `22` as host port `7422`:

```yaml
services:
  ssh:
    build: .
    container_name: sshkit-alpine-fixture
    restart: unless-stopped
    ports:
      - "7422:22"
    env_file:
      - .env
    volumes:
      - ./authorized_keys:/fixture/authorized_keys:ro
```

For that topology, set `SSHKIT_LIVE_PORT=7422` for the client connection from the developer machine, and keep `SSHKIT_LIVE_REMOTE_SSHD_PORT=22` for fixture-internal loopback targets such as `127.0.0.1:22`. The fixture `.env` file owns the root password and stays outside the repository.

The Docker image should install both OpenSSH server and client packages so the live suite can exercise SCP through the real fixture:

```dockerfile
RUN apk add --no-cache openssh-server openssh-client shadow \
    && mkdir -p /run/sshd /root/.ssh /fixture \
    && chmod 700 /root/.ssh
```

## Fixture Requirements

The required Alpine fixture should support:

- password authentication
- public-key authentication
- keyboard-interactive authentication
- authentication failure for wrong-password attempts
- exec channels
- PTY shell channels
- SFTP subsystem
- SCP client/server support
- direct TCP forwarding
- local, remote, and dynamic TCP forwarding
- SOCKS5 dynamic forwarding to loopback targets on the fixture host
- ProxyJump from the fixture back to its own loopback sshd
- `nc` for remote-forward command verification
- `sleep` for cancellation tests
- `dd` for SFTP transfer cancellation tests

The current shared Alpine container publishes `7422:22`, runs OpenSSH inside the container, uses `internal-sftp`, and includes `openssh-client` so `/usr/bin/scp` is available for SCP round-trip tests. The shared Alpine fixture currently reports `kbdinteractiveauthentication no`, so keyboard-interactive is recorded as a fixture-capability skip until that fixture is configured to advertise it.

Dropbear and legacy RSA are extra live fixtures. Set the `SSHKIT_DROPBEAR_*` and `SSHKIT_LEGACY_RSA_*` variables when those external services are available.

`SSHKIT_LIVE_HOST`, `SSHKIT_LEGACY_RSA_HOST`, and `SSHKIT_DROPBEAR_HOST` must point at external fixture hosts when set. Live tests reject loopback and localhost values so they exercise real SSH servers outside the developer machine's local sshd.

The live suite also mutates the supplied known-hosts entry to verify host-key mismatch failures, and it starts local loopback proxy/listener processes only as route fixtures while keeping the SSH server target on the external fixture host.

Run the full live gate with:

```sh
Script/test-live-fixture.sh
```

The live gate runs `swift test --no-parallel --filter LiveSSHTests` because the external Alpine fixture is a shared mutable resource. `LiveSSHTestCase` also takes a fixture lock when `SSHKIT_RUN_LIVE_TESTS=1`, so direct SwiftPM or Xcode invocations with parallel execution still queue the live XCTest cases against the same external fixture. Individual tests keep their own local temporary directories, local ephemeral ports, remote `/tmp/sshkit-*-<UUID>` paths, and unique Keychain service names.

The live gate requires the Alpine fixture tests to run. Dropbear, legacy RSA, and keyboard-interactive are treated as fixture-capability skips unless those extra services are configured.

The smoke command used by the current live tests is:

```sh
whoami && cat /etc/alpine-release
```

The expected Alpine fixture output starts with the fixture user and one Alpine release line:

```text
root
<major>.<minor>[.<patch>]
```

## Credential Handling

Fixture credentials live outside the repository in environment variables or a local, gitignored secrets file. Rotate fixture credentials after accidental disclosure and update the live-test environment before the next run.
