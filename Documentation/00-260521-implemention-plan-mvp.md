# SSHKit Implementation Plan

This plan covers the full SSHKit implementation loop. It is written as a working checklist for incremental development, review, and validation.

## Fixed Product Decisions

- SSHKit supports iOS, macOS, Mac Catalyst, tvOS, and visionOS.
- SSHKit excludes watchOS.
- SSHKit targets the lowest practical Apple platform floor:
  - iOS 13.0
  - macOS 10.15
  - Mac Catalyst 13.0
  - tvOS 13.0
  - visionOS 1.0
- SSHKit products are dynamic libraries.
- SSHKit uses libssh `0.12.x`.
- SSHKit uses `openssl-spm` for OpenSSL.
- SSHKit links zlib through the system `z` library.
- SSHKit exposes Swift and Objective-C APIs.
- Swift async APIs are primary.
- Swift callback APIs are provided.
- Objective-C callback APIs are public.
- One TCP socket owns one libssh `ssh_session`.
- One `SSHConnection` runs one active high-level job at a time.
- Concurrent high-level jobs use multiple `SSHConnection` instances.
- SSHKit uses blocking libssh calls.
- Public cancellation shuts down the socket immediately.
- The worker queue owns libssh cleanup and fd close.
- Caller misuse fails loudly in debug builds.
- Trust storage is dependency-injectable.
- SSHKit requires complete structured logging for observability, and the logging framework is dependency-injectable.
- The default Keychain trust-store service is `wiki.qaq.sshkit`.

## Success Criteria

The implementation is complete when SSHKit can:

- connect to OpenSSH and Dropbear servers
- authenticate with password, private key, keyboard-interactive, and agent
- validate host keys through known hosts, pinned fingerprints, Keychain trust store, memory store, and explicit insecure accept-any policy
- run collected commands
- run streamed commands
- open PTY shells
- perform SFTP operations
- perform SCP single-file transfers
- open direct TCP channels
- perform local, remote, and dynamic forwarding
- connect through SOCKS5 and HTTP CONNECT proxies
- connect through ProxyJump
- expose structured diagnostics
- expose algorithm profile and legacy RSA controls
- cancel connect, command, shell, SFTP, and forwarding operations promptly through socket shutdown
- build and test on all supported Apple platforms

## Repository Shape

Final top-level structure:

```text
Documentation/
  Design.md
  Roadmap.md
  ImplementationPlan.md
Package.swift
Script/
  vendor-libssh.sh
  test-destinations.sh
Sources/
  CLibSSH/
  SSHKitObjC/
  SSHKit/
Tests/
  SSHCoreObjCTests/
  SSHKitTests/
  LiveSSHTests/
Vendor/
  libssh/
```

Target responsibilities:

| Target | Responsibility |
| --- | --- |
| `CLibSSH` | vendored libssh source, generated config, OpenSSL backend, zlib |
| `SSHKitObjC` | Objective-C API, worker queue, libssh handles, socket fd, cancellation, NSError |
| `SSHKit` | Swift API, async wrappers, callback wrappers, typed errors, Sendable values |
| `SSHCoreObjCTests` | Objective-C unit tests |
| `SSHKitTests` | Swift API unit tests |
| `LiveSSHTests` | optional integration tests against real SSH servers |

## Naming Checklist

Swift public API:

- `SSHClient`
- `SSHClient.Configuration`
- `SSHAuthentication`
- `SSHHostKeyPolicy`
- `SSHHostTrustStore`
- `SSHConnection`
- `SSHCommand`
- `SSHCommandResult`
- `SSHShell`
- `SSHShellEvent`
- `SFTPClient`
- `SFTPFileHandle`
- `SFTPEntry`
- `SFTPAttributes`
- `SSHTunnelChannel`
- `SSHError`
- `SSHLogHandler`
- `SSHLogRecorder`

Objective-C public API:

- `SSHKitClient`
- `SSHKitConfiguration`
- `SSHKitAuthentication`
- `SSHKitHostKeyPolicy`
- `SSHKitHostTrustStore`
- `SSHKitKeychainTrustStore`
- `SSHKitMemoryTrustStore`
- `SSHKitConnection`
- `SSHKitCommand`
- `SSHKitCommandResult`
- `SSHKitShell`
- `SSHKitShellEvent`
- `SSHKitSFTPClient`
- `SSHKitSFTPFileHandle`
- `SSHKitTunnelChannel`
- `SSHKitError`
- `SSHKitLogHandler`
- `SSHKitLogRecorder`

Objective-C internal API:

- `SSHCoreSessionWorker`
- `SSHCoreSocketHandle`
- `SSHCoreCancellationToken`
- `SSHCoreChannel`
- `SSHCoreCommandRunner`
- `SSHCoreShellRunner`
- `SSHCoreSFTPRunner`
- `SSHCoreTunnelRunner`
- `SSHCoreKnownHosts`
- `SSHCoreHostKey`
- `SSHCoreErrorMapper`

## Threading And State Rules

Permanent rules:

- Every `SSHConnection` owns one `SSHCoreSessionWorker`.
- Every `SSHCoreSessionWorker` owns one serial dispatch queue.
- Every `SSHCoreSessionWorker` owns one socket fd.
- Every `SSHCoreSessionWorker` owns one libssh `ssh_session`.
- Every active job owns at most one libssh channel.
- No libssh handle is accessed outside the worker queue.
- The main thread may call public `cancel` or `close`.
- Public `cancel` and `close` call `SSHCoreSocketHandle.shutdownNow()`.
- `SSHCoreSocketHandle.shutdownNow()` may run on any thread.
- Only the worker queue calls `close(fd)`.
- `close()` is idempotent.
- All other invalid state transitions fail loudly in debug builds.

Connection states:

```text
idle
connecting
ready
runningCommand
runningShell
runningSFTP
runningTunnel
closing
closed
```

Allowed transitions:

| From | To | Trigger |
| --- | --- | --- |
| `idle` | `connecting` | `connect` starts |
| `idle` | `closing` | `close` starts before connection |
| `connecting` | `ready` | authentication succeeds |
| `connecting` | `closed` | connect fails or is cancelled |
| `ready` | `runningCommand` | `execute` or `openCommand` |
| `runningCommand` | `ready` | command finishes |
| `ready` | `runningShell` | `openShell` |
| `runningShell` | `ready` | shell closes cleanly |
| `ready` | `runningSFTP` | `openSFTP` |
| `runningSFTP` | `ready` | SFTP closes cleanly |
| `ready` | `runningTunnel` | forwarding starts |
| `runningTunnel` | `ready` | tunnel closes cleanly |
| any active state | `closing` | `close` or cancellation |
| `closing` | `closed` | cleanup completes |

Invalid examples:

- calling `execute` while `runningShell`
- calling `openSFTP` while `runningCommand`
- calling `openShell` after `closed`
- calling `write` on a closed shell
- reading an SFTP handle after close

## Fail-Loud Rules

Debug behavior:

- invalid input crashes with `preconditionFailure`, `NSParameterAssert`, or `NSInvalidArgumentException`
- invalid state crashes with `preconditionFailure` or `NSInternalInconsistencyException`
- impossible libssh states crash
- silent fallback is forbidden

Release behavior:

- runtime failures return typed Swift errors or `NSError`
- closed-object use returns a typed error where the API can throw or callback
- `close()` remains idempotent
- unexpected internal corruption still crashes

Runtime failures:

- TCP connect failure
- timeout
- cancellation
- server disconnect
- host-key mismatch
- authentication failure
- protocol error
- SFTP status error
- local file I/O error
- proxy route failure

## P0: Foundation And Collected Commands

### P0.1 Package And Dependencies

Tasks:

- lower platform floors in `Package.swift`
- keep products dynamic
- add `KeychainAccess`
- add `SSHCoreObjCTests`
- keep `SSHKitTests`
- add `LiveSSHTests`
- add multi-destination test script

Acceptance:

- `swift test` passes on macOS
- package resolves without warnings
- package builds dynamic libraries
- supported platform destinations build where local Xcode supports them

### P0.2 Vendor libssh

Tasks:

- vendor libssh `0.12.x`
- include upstream license files
- generate `libssh_version.h`
- generate Apple config header
- select client-focused source list
- enable OpenSSL backend
- enable zlib
- enable SFTP compile support for later phases
- disable examples and tests
- exclude server support unless required by client APIs
- document libssh build settings

Acceptance:

- `CLibSSH` builds
- `ssh_new` can be linked from `SSHKitObjC`
- license files are present
- `swift test` still passes

### P0.3 Objective-C API Rename

Tasks:

- rename current ObjC public types to `SSHKit*`
- add public umbrella header
- keep `SSHKitObjC` product public
- rename internal placeholders to `SSHCore*`
- update Swift bridge imports

Acceptance:

- Objective-C public headers compile
- Swift imports `SSHKitObjC`
- no old `GSSH*` public symbols remain

### P0.4 Core Worker

Tasks:

- implement `SSHCoreSessionWorker`
- implement `SSHCoreSocketHandle`
- implement `SSHCoreCancellationToken`
- implement state machine
- implement worker queue assertion helpers
- implement fail-loud state checks
- implement cancellation state

Acceptance:

- unit tests cover state transitions
- invalid transition crashes in debug test harness where practical
- `close()` is idempotent
- socket handle avoids fd double-close

### P0.5 TCP Connect And libssh Session

Tasks:

- create TCP socket manually
- configure connect timeout
- connect to host and port
- hand fd to libssh with `SSH_OPTIONS_FD`
- set host, port, username
- run `ssh_connect`
- run server identification and key exchange through libssh
- map libssh errors to `SSHKitError`

Acceptance:

- connect succeeds against the external OpenSSH fixture in live tests
- connect failure returns typed error
- cancellation during connect returns cancellation
- socket fd closes once

### P0.6 Authentication

Tasks:

- implement password auth
- implement private-key-file auth
- support passphrase
- map auth failures to typed errors
- capture auth banners where libssh exposes them

Acceptance:

- password login live test passes
- key-file login live test passes
- wrong password returns auth failure
- cancellation during auth closes connection

### P0.7 Host Trust

Tasks:

- implement known-hosts file policy
- implement pinned fingerprint policy
- implement memory trust store
- implement Keychain trust store using service `wiki.qaq.sshkit`
- implement explicit `insecureAcceptAnyHostKey`
- expose dependency injection for trust stores
- expose host-key fingerprint in connection metadata
- log warning for insecure policy

Acceptance:

- known-hosts match passes
- known-hosts mismatch returns host-key error
- pinned fingerprint match passes
- pinned fingerprint mismatch returns host-key error
- Keychain trust store can save and load host key
- memory trust store can save and load host key

### P0.8 Collected Command

Tasks:

- implement `SSHConnection.execute`
- open session channel
- request exec
- collect stdout
- collect stderr
- capture exit status
- capture exit signal where available
- close channel
- map libssh channel errors

Acceptance:

- `execute("echo ok")` returns stdout
- stderr is captured
- non-zero exit status is returned in result
- command cancellation closes connection
- executing while shell/SFTP/tunnel is active fails loudly

### P0.9 Swift Async And Callback API

Tasks:

- implement async connect with continuation
- implement async execute
- implement async close
- implement scoped `withConnection`
- implement callback connect
- implement callback execute
- adopt `Task` cancellation by calling ObjC cancellation
- mark public value types `Sendable` where valid

Acceptance:

- `try await SSHClient.connect` works
- `try await SSHClient.withConnection` closes on success
- `withConnection` closes on throw
- Task cancellation triggers socket shutdown
- callback APIs work from main queue

## P1: Shell, Streamed Commands, Auth Discovery, Diagnostics

### P1.1 Streamed Commands

Tasks:

- implement `SSHCommand`
- open exec channel without collected buffering
- expose stdout/stderr events
- expose stdin writes
- expose EOF
- expose exit status and signal
- expose `AsyncSequence`
- expose callback event handler

Acceptance:

- long-running command streams output
- stdin can be written
- cancellation closes connection
- events finish exactly once

### P1.2 PTY Shell

Tasks:

- implement `SSHShell`
- request PTY
- request shell
- expose stdout/stderr events
- expose stdin writes
- expose resize
- expose EOF and close
- support terminal type and size

Acceptance:

- shell starts against OpenSSH
- shell echoes commands
- resize request succeeds
- shell cancellation closes connection
- writing after close fails loudly in debug

### P1.3 Keyboard-Interactive And Discovery

Tasks:

- implement keyboard-interactive auth
- expose prompt callback
- implement auth method discovery
- expose auth banners
- map partial success

Acceptance:

- keyboard-interactive live test passes
- discovery returns advertised methods
- cancellation during prompts closes connection

### P1.4 Diagnostics

Tasks:

- implement `SSHLogHandler`
- implement `SSHLogRecorder`
- implement redaction
- implement Swift typed errors
- implement `NSError` domain and codes
- implement diagnostic report
- include connection phase, host, port, username, and redacted metadata

Acceptance:

- logs are emitted for connect, auth, trust, command, shell, close
- sensitive values are redacted
- bounded recorder evicts old events
- diagnostic report contains useful support data

## P2: SFTP

### P2.1 SFTP Client

Tasks:

- open SFTP subsystem
- initialize libssh SFTP session
- implement close
- implement realpath
- implement stat and lstat
- implement set attributes
- implement filesystem attributes where available

Acceptance:

- SFTP opens against OpenSSH
- stat returns metadata
- close is idempotent
- SFTP blocks other jobs on same connection

### P2.2 Directory And File Operations

Tasks:

- list directory
- create directory
- remove directory
- remove file
- rename
- read link
- create symbolic link
- open file handle
- close file handle

Acceptance:

- full temp directory lifecycle passes live tests
- invalid paths return SFTP errors
- handle after close fails loudly in debug

### P2.3 Transfer Helpers

Tasks:

- read whole remote file
- write whole remote file
- download to local URL
- upload from local URL
- emit progress callbacks
- implement chunk streaming
- implement resumable upload
- implement resumable download

Acceptance:

- upload/download round trip passes
- progress is monotonic
- cancellation closes connection
- local file errors surface as typed errors

## P3: Forwarding, Routing, SCP

### P3.1 Direct TCP And Local Forwarding

Tasks:

- implement direct TCP channel
- implement local listener
- bridge local socket to SSH channel
- expose cancellation
- enforce one active tunnel per connection

Acceptance:

- direct TCP channel reaches target
- local forwarding works through SSH server
- cancellation closes connection

### P3.2 Remote And Dynamic Forwarding

Tasks:

- implement remote TCP forwarding
- implement accepted remote channels
- implement dynamic SOCKS forwarding
- support SOCKS5 no-auth
- support SOCKS5 username/password

Acceptance:

- remote forwarding live test passes
- SOCKS dynamic forwarding can reach HTTP test server
- cancellation closes connection

### P3.3 Proxy Routes

Tasks:

- implement SOCKS5 outer proxy
- implement HTTP CONNECT outer proxy
- implement ProxyJump
- make each jump host its own `SSHConnection` internally
- keep one active job rule visible to the public API

Acceptance:

- direct proxy route connects
- HTTP CONNECT route connects
- ProxyJump route connects
- route failures report which hop failed

### P3.4 SCP

Tasks:

- implement single-file receive
- implement single-file send
- validate remote paths
- validate filenames
- bound receive size
- capture remote scp errors

Acceptance:

- SCP upload/download passes
- invalid names are rejected
- oversized receive fails safely

## P4: Advanced Capabilities

### P4.1 Agent And Keys

Tasks:

- implement SSH agent auth
- implement agent candidate selection
- implement OpenSSH key generation helpers
- implement authorized-key export
- implement Keychain credential helpers

Acceptance:

- agent auth works against OpenSSH
- generated key can authenticate after installation
- Keychain credentials can be loaded by app code

### P4.2 Algorithms

Tasks:

- expose algorithm profile inspection
- expose legacy RSA opt-in
- expose custom algorithm profile
- document libssh-supported algorithm limits
- add compatibility tests against legacy endpoints

Acceptance:

- caller can inspect effective algorithms
- legacy RSA opt-in changes libssh options
- default profile stays modern

### P4.3 Latency And Tooling

Tasks:

- implement port latency measurement
- measure direct route
- measure proxy route
- measure ProxyJump route
- add release packaging scripts
- add multi-destination CI

Acceptance:

- latency reports include connect timing and SSH service timing
- CI builds supported destinations
- release process is documented

## Test Strategy

Unit tests:

- configuration validation
- state machine transitions
- socket handle shutdown/close behavior
- cancellation token behavior
- trust store serialization
- error mapping
- log redaction

Async tests:

- cancellation before connect completes
- cancellation during execute
- cancellation during shell
- cancellation during SFTP transfer
- scoped connection closes on success
- scoped connection closes on throw

Live tests:

- Alpine fixture password auth smoke command
- Alpine fixture private-key auth smoke command
- Alpine fixture known-hosts validation
- OpenSSH password auth
- OpenSSH key auth
- OpenSSH known hosts
- OpenSSH shell
- OpenSSH SFTP
- OpenSSH forwarding
- Dropbear command execution
- ProxyJump
- SOCKS5 route
- HTTP CONNECT route

Live tests must be opt-in with `SSHKIT_RUN_LIVE_TESTS=1`.

## Review Checklist

Every PR or implementation loop should check:

- public API names match the naming checklist
- ObjC public names use `SSHKit` prefix
- internal ObjC names use `SSHCore` prefix
- no libssh handle escapes the worker queue
- one active job rule is enforced
- `close()` is idempotent
- other invalid state transitions fail loudly
- cancellation calls socket shutdown
- worker queue owns fd close
- errors are typed
- logs are redacted
- tests cover success and failure paths
- no silent fallback hides broken state

## Known Risks

| Risk | Mitigation |
| --- | --- |
| Blocking libssh calls occupy worker threads | one worker per connection, one active job per connection |
| main-thread cancellation races fd reuse | main thread calls `shutdown`, worker queue calls `close` |
| host trust persistence differs by platform | injectable store, Keychain default, memory store tests |
| libssh source configuration drift | generated config checked into source and tested in CI |
| LGPL compliance | dynamic products, license files, documented source boundary |
| multi-platform binary dependency mismatch | destination builds and OpenSSL package validation |
| API misuse hidden as runtime error | debug fail-loud policy |

## First Implementation Loop

The first coding loop should complete P0.1 through P0.4:

1. lower platform floors
2. add KeychainAccess
3. rename ObjC public types
4. add `SSHCoreSessionWorker`
5. add `SSHCoreSocketHandle`
6. add `SSHCoreCancellationToken`
7. add state machine tests
8. run `swift test`
9. commit and push

After that, wire libssh and implement real connect/auth.
