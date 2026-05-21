# SSHKit Roadmap

This roadmap lists the implementation plan for the confirmed SSHKit design.

MVP status: P0 through P4 are implemented in the current MVP branch. Remaining release validation requires running `Script/test-live-fixture.sh` with the external fixture environment.

## P0: Foundation

Deliver the package foundation and the first reliable command path.

- Lower platform floors to iOS 13, macOS 10.15, Mac Catalyst 13, tvOS 13, and visionOS 1.
- Keep all library products dynamic.
- Add `KeychainAccess` for default trust-store persistence.
- Vendor libssh `0.12.x` under `Vendor/libssh`.
- Generate Apple platform config headers for libssh.
- Build `CLibSSH` with OpenSSL and zlib.
- Rename Objective-C public APIs to the `SSHKit` prefix.
- Introduce internal `SSHCore` types.
- Add `SSHCoreSessionWorker`.
- Add `SSHCoreSocketHandle`.
- Add `SSHCoreCancellationToken`.
- Implement blocking TCP connect with owned fd.
- Pass the owned fd to libssh with `SSH_OPTIONS_FD`.
- Implement `SSHClient.connect`.
- Implement `SSHClient.withConnection`.
- Implement password authentication.
- Implement private-key-file authentication.
- Implement known-hosts trust.
- Implement Keychain-backed trust store with service `wiki.qaq.sshkit`.
- Implement pinned fingerprint trust.
- Implement explicit `insecureAcceptAnyHostKey`.
- Implement collected command execution.
- Implement `SSHConnection.close`.
- Implement Task cancellation by calling socket shutdown.
- Implement callback APIs that mirror async APIs.
- Add fail-loud assertions for programmer misuse.
- Add tests for configuration, invalid state, cancellation, and command lifecycle.

## P1: Shell And Diagnostics

Deliver interactive terminal use and clear support diagnostics.

- Implement streamed command channels.
- Implement PTY shell startup.
- Implement shell stdin writes.
- Implement shell stdout and stderr events.
- Implement PTY resize.
- Implement streamed command EOF handling and exit signal metadata.
- Implement keyboard-interactive authentication.
- Implement authentication method discovery.
- Add structured log events.
- Add bounded log recorder.
- Add redacted diagnostic reports.
- Add Objective-C error domain coverage.
- Add Swift typed error coverage.
- Add live tests for OpenSSH command and shell flows.

## P2: SFTP

Deliver file transfer APIs.

- Implement SFTP subsystem startup.
- Implement `SFTPClient`.
- Implement `SFTPFileHandle`.
- Implement `realPath`.
- Implement `stat` and `lstat`.
- Implement file attribute updates.
- Implement directory listing.
- Implement file read and write.
- Implement local file upload and download helpers.
- Implement mkdir and rmdir.
- Implement remove file.
- Implement rename.
- Implement symlink and readlink.
- Implement progress callbacks.
- Implement chunked reads and writes.
- Implement resumable upload and download helpers.
- Add SFTP status error mapping.
- Add tests for file lifecycle and transfer cancellation.

## P3: Forwarding, Routing, And SCP

Deliver network routing and compatibility transfer helpers.

- Implement direct TCP channels.
- Implement local port forwarding.
- Implement remote port forwarding.
- Implement dynamic forwarding.
- Implement SOCKS5 proxy route.
- Implement HTTP CONNECT proxy route.
- Implement ProxyJump.
- Implement SCP single-file receive.
- Implement SCP single-file send.
- Implement remote path validation for SCP.
- Implement forwarding cancellation through socket shutdown.
- Add live tests for local forwarding, remote forwarding, and ProxyJump.

## P4: Advanced Capabilities

Deliver advanced integration and tooling.

- Implement SSH agent authentication.
- Implement OpenSSH key generation helpers.
- Implement Keychain credential helpers.
- Implement algorithm profile inspection.
- Implement legacy RSA opt-in.
- Implement custom algorithm profile configuration.
- Implement latency measurement tools.
- Add broader compatibility validation against OpenSSH, Dropbear, and common proxy setups.
- Add release packaging and multi-destination CI.

## Permanent Architecture Rules

- One TCP socket owns one libssh `ssh_session`.
- One `SSHConnection` runs one active high-level job at a time.
- Concurrent high-level jobs use multiple `SSHConnection` instances.
- All libssh calls run on the connection worker queue.
- Public cancellation calls socket shutdown immediately.
- The worker queue owns libssh cleanup and fd close.
- Caller misuse fails loudly in debug builds.
- Runtime failures surface as typed Swift errors and `NSError` values.
- Trust storage is dependency-injectable.
- The default Keychain trust store uses service `wiki.qaq.sshkit`.
