# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

```sh
# Format (always run before committing source/test changes)
swiftformat Sources Tests --swiftversion 6.2

# Build + unit tests (no live fixture)
swift test

# Run a single test
swift test --filter SSHKitTests.SSHPortLatencyTests/testSomething

# All Apple destinations (used by CI in .github/workflows/ci.yml)
Script/test-destinations.sh

# Live SSH suite against the external Alpine/legacy-RSA/Dropbear fixtures.
# Requires the env vars in Documentation/Fixtures/AlpineSSH.md
# (SSHKIT_RUN_LIVE_TESTS=1, SSHKIT_LIVE_HOST/PORT/USERNAME/PASSWORD/KNOWN_HOSTS/PRIVATE_KEY).
# The script rejects loopback hosts — the fixture must be remote.
Script/test-live-fixture.sh

# Re-vendor libssh (overwrites Vendor/libssh/{src,include,COPYING,AUTHORS})
Script/vendor-libssh.sh 0.12.0

# Build a release tarball (requires a clean checkout)
Script/package-release.sh
```

Live tests are gated behind `SSHKIT_RUN_LIVE_TESTS=1` and run with `--no-parallel` (see `Script/test-live-fixture.sh`). The `LiveSSHTests` target also lives inside `swift test`; without the env vars these tests skip themselves.

## Architecture

The package is a three-layer wrapper around vendored libssh, exposed as **dynamic** library products so the LGPL boundary around libssh stays explicit for apps.

```
CLibSSH         (C)      Vendor/libssh + OpenSSL backend + zlib (Sources/CLibSSH/include holds module map + config.h)
   │
SSHKitObjC      (Obj-C)  Public API (SSHKit* prefix) + internal core (SSHCore* prefix)
   │                     Owns ssh_session, socket fd, worker queue, cancellation
SSHKit          (Swift)  Async/await + callback APIs, typed errors, value types
```

Public Swift entry point is `SSHClient` (`Sources/SSHKit/SSHClient.swift`), which produces an `SSHConnection`. `SSHConnection` is a thin Swift wrapper over `SSHKitConnection` (Obj-C). The Obj-C public façade in `Sources/SSHKitObjC/*.m` writes through to `SSHCoreSessionWorker` (in `Sources/SSHKitObjC/Private/`), which is the single owner of the worker queue, socket, and libssh session.

### Ownership invariants — do not break these

1. **One TCP socket owns one `ssh_session`.** The fd is created by SSHKit and passed to libssh via `SSH_OPTIONS_FD`. `SSHCoreSocketHandle` arbitrates cross-thread fd state.
2. **One `SSHConnection` runs one active high-level job at a time** — collected command, streamed command, PTY shell, SFTP, or tunnel. Concurrent work requires additional connections; SSHKit deliberately exposes no multiplexing.
3. **All libssh calls run on the connection's serial worker queue.** Public APIs may be invoked from any thread; they enqueue work or request cancellation.
4. **Cancellation goes through `shutdown(fd, SHUT_RDWR)`**, called from any thread by `SSHCoreSocketHandle.shutdownNow()`. The worker queue then unwinds libssh and calls `close(fd)` via `takeFileDescriptorForClose()` to avoid fd-reuse races. `EBADF`/`ENOTCONN` during shutdown is expected and logged at debug only.

The Swift connect/disconnect paths use `SSHLockedSession` (private to `SSHClient.swift`) to bridge `Task` cancellation onto the Obj-C disconnect path; preserve that pattern when adding new async entry points.

### Fail-loud policy

Caller misuse (invalid state transitions, calling into a closed object on non-throwing APIs, programmer-supplied bad input) must crash in debug:

- Swift: `preconditionFailure`.
- Obj-C: `NSParameterAssert` / `NSAssert` / `NSInvalidArgumentException`.

Runtime conditions (network loss, auth rejection, host-key mismatch, SFTP status, etc.) surface as `SSHKitError` / `NSError` instead. `close()` is always idempotent. The connection state machine is documented in `Documentation/Design.md` ("State Model"); follow it when adding new operations.

### Host trust

`SSHHostKeyPolicy` is the choice point: `.knownHostsFile`, `.trustStore`, `.pinnedFingerprint`, `.insecureAcceptAnyHostKey`. Use `SSHClient.discoverHostKey` for first-time host-key collection, then let the app/UI save the approved fingerprint into an `SSHHostTrustStore` before connecting with `.trustStore`. The default Keychain trust store uses service name `wiki.qaq.sshkit` — do not change that string lightly (it's the user-visible Keychain identifier).

### Algorithm profiles

`SSHAlgorithmProfile.modern` (libssh defaults + RSA ≥ 3072) and `.legacyRSA` (opts back into `ssh-rsa`, RSA ≥ 1024) are the two named profiles. Custom profiles pass comma-separated lists straight to libssh and may use the `+`/`-`/`^` modifiers. libssh's allowed-algorithm surface is bounded by the vendored libssh/OpenSSL build.

## Tests

Three test targets:

- `SSHCoreObjCTests` — Obj-C-level unit tests against `SSHKitObjC`.
- `SSHKitTests` — Swift unit tests.
- `LiveSSHTests` — opt-in integration tests against an external SSH fixture. Helpers live in `Tests/LiveSSHTests/LiveSSHTestSupport.swift`. Suite covers auth (password / pubkey / keyboard-interactive / agent), host trust, commands (collected + streamed), shell/PTY, SFTP, SCP, direct/local/remote/dynamic forwarding, proxy routes, cancellation, and scoped connections.

## Source layout pointers

- `Sources/SSHKit/` — Swift public API. One file per public concept (`SSHClient`, `SSHConnection`, `SSHCommand`, `SSHShell`, `SFTPClient`, `SCPClient`, `SSHTunnelChannel`, `SSHPortLatency`, etc.).
- `Sources/SSHKitObjC/` — Public Obj-C headers in `include/SSHKitObjC/`; internal headers + worker/socket/cancellation code in `Private/`. The bulk of the libssh-touching logic lives in `SSHCoreOpenSSHClient.m`.
- `Sources/CLibSSH/include/` — `module.modulemap`, generated `config.h` for Apple platforms, and libssh public headers. `placeholder.c` exists so SwiftPM has a compilable source in the target root.
- `Vendor/libssh/` — vendored libssh source (LGPL). Regenerate with `Script/vendor-libssh.sh`; the explicit source list in `Package.swift` (`libsshSources`) must be updated when libssh's tree changes.
- `Documentation/Design.md` — authoritative design doc; consult before changing ownership, threading, or state-machine rules.
- `Documentation/Roadmap.md` — phased capability inventory (P0–P4) and the permanent architecture rules.

## Platform targets

iOS 13 / macOS 10.15 / Mac Catalyst 13 / tvOS 13 / visionOS 1. watchOS is intentionally unsupported. All library products are `.dynamic`.
