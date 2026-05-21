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
export SSHKIT_LEGACY_RSA_HOST="legacy-rsa.example.com"
export SSHKIT_LEGACY_RSA_PORT="22"
export SSHKIT_LEGACY_RSA_USERNAME="root"
export SSHKIT_LEGACY_RSA_PASSWORD="<password>"
export SSHKIT_LEGACY_RSA_KNOWN_HOSTS="<known-hosts-entry>"
export SSHKIT_DROPBEAR_HOST="dropbear.example.com"
export SSHKIT_DROPBEAR_PORT="22"
export SSHKIT_DROPBEAR_USERNAME="root"
export SSHKIT_DROPBEAR_PASSWORD="<password>"
export SSHKIT_DROPBEAR_KNOWN_HOSTS="<known-hosts-entry>"
```

Each known-hosts value should contain one complete OpenSSH known-hosts line. `SSHKIT_LIVE_PRIVATE_KEY` should contain a private key accepted by the Alpine fixture user. The legacy RSA fixture uses `SSHAlgorithmProfile.legacyRSA`, password authentication, known-host verification, and a real exec channel. The Dropbear fixture uses password authentication, known-host verification, and a real exec channel.

## Fixture Requirements

The server should support:

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

`SSHKIT_LIVE_HOST`, `SSHKIT_LEGACY_RSA_HOST`, and `SSHKIT_DROPBEAR_HOST` must point at external fixture hosts. Live tests reject loopback and localhost values so they exercise real SSH servers outside the developer machine's local sshd.

The live suite also mutates the supplied known-hosts entry to verify host-key mismatch failures, and it starts local loopback proxy/listener processes only as route fixtures while keeping the SSH server target on the external fixture host.

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
