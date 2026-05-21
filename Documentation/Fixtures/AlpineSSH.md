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
```

`SSHKIT_LIVE_KNOWN_HOSTS` should contain one complete OpenSSH known-hosts line. `SSHKIT_LIVE_PRIVATE_KEY` should contain a private key accepted by the fixture user.

## Fixture Requirements

The server should support:

- password authentication
- public-key authentication
- exec channels
- PTY shell channels
- SFTP subsystem
- direct TCP forwarding
- local, remote, and dynamic TCP forwarding
- SOCKS5 dynamic forwarding to loopback targets on the fixture host
- `nc` for remote-forward command verification

`SSHKIT_LIVE_HOST` must point at an external fixture host. Live tests reject loopback and localhost values so they exercise a real SSH server outside the developer machine's local sshd.

The smoke command used by the current live tests is:

```sh
whoami && cat /etc/alpine-release
```

The expected current Alpine fixture output is:

```text
root
3.21.7
```

## Credential Handling

Fixture credentials live outside the repository in environment variables or a local, gitignored secrets file. Rotate fixture credentials after accidental disclosure and update the live-test environment before the next run.
