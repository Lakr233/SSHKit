# SSHKit Design

SSHKit is a dynamic Swift package for libssh on Apple platforms. The package wraps libssh with an Objective-C core and exposes Swift 6 friendly APIs for applications.

## Goals

- Support Apple platforms that can act as TCP clients: iOS, macOS, Mac Catalyst, tvOS, and visionOS.
- Use dynamic library products so the libssh LGPL boundary stays explicit for application packaging.
- Keep libssh handles inside Objective-C objects with clear thread ownership.
- Make Swift the primary API layer, with async/await, Task cancellation adoption, Sendable-friendly values, and callback APIs.
- Expose Objective-C APIs for Objective-C applications.
- Keep one SSH connection focused on one active high-level job for the lifetime of the library design.
- Surface programmer mistakes loudly during development.

## Platform Floor

The package should target the lowest practical Apple versions supported by the compiled dependencies:

| Platform | Target Floor |
| --- | --- |
| iOS | 13.0 |
| macOS | 10.15 |
| Mac Catalyst | 13.0 |
| tvOS | 13.0 |
| visionOS | 1.0 |

watchOS stays outside the supported platform set.

## Package Shape

The repository follows the source-package shape used by `Lakr233/libssh2-spm`: upstream source lives under `Vendor`, C compile settings live in `Package.swift`, and application APIs live in separate wrapper targets.

Products:

- `CLibSSH`: dynamic C library product for the vendored libssh source target.
- `SSHKitObjC`: dynamic Objective-C wrapper product.
- `SSHKit`: dynamic Swift API product.

Targets:

- `CLibSSH`: vendored libssh C source, generated config headers, OpenSSL backend, zlib, and Apple platform compile settings.
- `SSHKitObjC`: Objective-C public API, libssh handle ownership, socket ownership, cancellation, and error bridging.
- `SSHKit`: Swift API surface, async wrappers, typed errors, value types, and callback conveniences.

Crypto backend:

- Use `https://github.com/Lakr233/openssl-spm` for libssh's OpenSSL backend.
- Link zlib through the system `z` library.
- Use Apple Security APIs for Keychain and trust-store integration where the application layer needs platform storage.

## Naming

SSHKit uses conventional SSH terms. Shared terms such as client, connection, session, channel, and SFTP are industry vocabulary.

Swift public names:

| Concept | Name |
| --- | --- |
| Entry point | `SSHClient` |
| Configuration | `SSHClient.Configuration` |
| Auth input | `SSHAuthentication` |
| Host trust policy | `SSHHostKeyPolicy` |
| Authenticated transport | `SSHConnection` |
| Collected command output | `SSHCommandResult` |
| Streamed command | `SSHCommand` |
| PTY shell | `SSHShell` |
| File subsystem | `SFTPClient` |
| File handle | `SFTPFileHandle` |
| Tunnel channel | `SSHTunnelChannel` |

Objective-C public names use the `SSHKit` prefix:

- `SSHKitClient`
- `SSHKitConfiguration`
- `SSHKitAuthentication`
- `SSHKitHostKeyPolicy`
- `SSHKitHostTrustStore`
- `SSHKitConnection`
- `SSHKitCommandResult`
- `SSHKitShell`
- `SSHKitSFTPClient`
- `SSHKitTunnelChannel`

Objective-C internal names use the `SSHCore` prefix:

- `SSHCoreSessionWorker`
- `SSHCoreSocketHandle`
- `SSHCoreCancellationToken`
- `SSHCoreChannel`
- `SSHCoreSFTPHandle`

## Public API Direction

Swift async APIs are the primary application surface:

```swift
let configuration = SSHClient.Configuration(
    host: "example.com",
    username: "deploy",
    authentication: .password("secret"),
    hostKeyPolicy: .trustStore(.keychain(service: "wiki.qaq.sshkit"))
)

let connection = try await SSHClient.connect(configuration)
let result = try await connection.execute("uname -a")
try await connection.close()
```

Scoped ownership:

```swift
let result = try await SSHClient.withConnection(configuration) { connection in
    try await connection.execute("uptime")
}
```

Callback APIs mirror the same operations:

```swift
SSHClient.connect(configuration) { result in
    switch result {
    case let .success(connection):
        connection.execute("uname -a") { commandResult in
        }
    case let .failure(error):
        print(error)
    }
}
```

Objective-C APIs use the same model:

```objc
SSHKitConfiguration *configuration =
    [[SSHKitConfiguration alloc] initWithHost:@"example.com"
                                     username:@"deploy"];

configuration.authentication = [SSHKitAuthentication password:@"secret"];
configuration.hostKeyPolicy =
    [SSHKitHostKeyPolicy keychainTrustStoreWithService:@"wiki.qaq.sshkit"];

[SSHKitClient connectWithConfiguration:configuration
                            completion:^(SSHKitConnection *connection, NSError *error) {
    [connection execute:@"uname -a"
             completion:^(SSHKitCommandResult *result, NSError *error) {
    }];
}];
```

## Ownership Model

SSHKit keeps a simple transport model:

```text
SSHClient
  |
  +-- SSHConnection
        |
        +-- SSHKitConnection
              |
              +-- SSHCoreSessionWorker
                    - one serial dispatch queue
                    - one TCP socket fd
                    - one ssh_session
                    - one cancellation token
                    |
                    +-- one active high-level job
                         - command
                         - shell
                         - SFTP
                         - tunnel
```

One TCP socket owns one libssh `ssh_session`. One `SSHConnection` runs one active high-level job at a time. The active job may be a collected command, a streamed command, a PTY shell, an SFTP subsystem, or a tunnel.

Concurrent SSH work uses multiple `SSHConnection` instances:

```text
shell:  socket A -> ssh_session A -> shell channel
SFTP:   socket B -> ssh_session B -> SFTP channel
tunnel: socket C -> ssh_session C -> tunnel channel
```

This stays true across the full library lifecycle. SSHKit keeps multiplexing out of the public model.

## Threading Model

SSHKit uses a blocking worker model.

Each `SSHConnection` owns one `SSHCoreSessionWorker`. The worker has one serial dispatch queue. GCD schedules that queue on a system thread when work is active. Blocking libssh calls can occupy that worker thread until completion or cancellation.

Thread ownership:

| Object | Queue Ownership | Socket Ownership | libssh Ownership |
| --- | --- | --- | --- |
| `SSHClient` | none | none | none |
| `SSHConnection` | none | none | Swift wrapper |
| `SSHKitConnection` | none | none | Objective-C public wrapper |
| `SSHCoreSessionWorker` | one serial queue | one fd | one `ssh_session` |
| `SSHShell` | worker queue | none | one `ssh_channel` through worker |
| `SSHCommand` | worker queue | none | one `ssh_channel` through worker |
| `SFTPClient` | worker queue | none | one SFTP subsystem channel |
| `SSHTunnelChannel` | worker queue | none | one forwarding channel |

Rules:

- All libssh calls run on the worker queue.
- Mutable operation state lives on the worker queue.
- Public methods may be called from any thread.
- Public methods enqueue work or request cancellation.
- Immutable request objects cross thread boundaries.
- Objective-C objects copy configuration values before enqueueing work.

## Blocking I/O Model

SSHKit uses blocking libssh operations for connection setup, authentication, commands, shells, SFTP, and tunnels.

The socket fd is created and owned by SSHKit. The fd is passed to libssh through `SSH_OPTIONS_FD`. `SSHCoreSocketHandle` owns cross-thread fd state with a lock.

Cancellation and close use this path:

1. The caller invokes `cancel()` or `close()` from any thread.
2. The public object marks the operation as cancelled or closing.
3. `SSHCoreSocketHandle.shutdownNow()` calls `shutdown(fd, SHUT_RDWR)`.
4. Any blocking connect/read/write inside libssh wakes up.
5. The worker queue maps the result to cancellation or close.
6. The worker queue performs libssh cleanup.
7. The worker queue closes the fd through `takeFileDescriptorForClose()`.

The main thread may call `shutdownNow()`. The worker queue performs `close(fd)`. This avoids fd reuse hazards.

`shutdown(fd, SHUT_RDWR)` can report `EBADF`, `ENOTCONN`, or related already-closed states on cancellation paths. SSHKit records those as debug diagnostics and continues cleanup.

## State Model

Connection states:

```text
idle
  -> connecting
  -> ready
  -> runningCommand
  -> ready
  -> runningShell
  -> ready
  -> runningSFTP
  -> ready
  -> runningTunnel
  -> ready
  -> closing
  -> closed
```

Only one running state is active at a time. `close()` is idempotent. Other invalid state transitions are programmer errors.

Examples:

| Current State | Call | Result |
| --- | --- | --- |
| `connecting` | `execute` | programming failure |
| `runningShell` | `openSFTP` | programming failure |
| `closing` | `execute` | programming failure |
| `closed` | `close` | idempotent success |
| `closed` | `openShell` | programming failure in debug, typed error in release |

## Fail-Loud Policy

SSHKit treats caller misuse as a programming failure.

Debug builds:

- Swift uses `preconditionFailure` for invalid object state.
- Objective-C uses `NSParameterAssert`, `NSAssert`, or `NSInvalidArgumentException` for invalid inputs and state transitions.
- Impossible libssh states crash during development.

Release builds:

- Runtime failures surface as typed errors.
- Closed-object use surfaces as typed errors where the API can throw or call back.
- `close()` remains idempotent.

Runtime failures include network loss, authentication rejection, host-key mismatch, server disconnect, protocol errors, and filesystem errors.

## Host Trust

Host trust is explicit and injectable.

Swift:

```swift
public enum SSHHostKeyPolicy {
    case knownHostsFile(String)
    case trustStore(HostTrustStore)
    case pinnedFingerprint(String)
    case insecureAcceptAnyHostKey
}
```

Objective-C:

- `SSHKitHostKeyPolicy`
- `SSHKitHostTrustStore`
- `SSHKitKeychainTrustStore`
- `SSHKitMemoryTrustStore`

Default Keychain service:

```text
wiki.qaq.sshkit
```

The default store uses Keychain-backed persistence. Applications may inject their own store implementation. KeychainAccess is an acceptable Swift dependency for the default Keychain-backed store. Direct Security.framework usage remains available inside Objective-C where lower-level control is useful.

`insecureAcceptAnyHostKey` is an explicit policy. It should emit a warning log event and should be suitable for local tools, tests, and controlled disposable environments.

## Diagnostics

Diagnostics should be structured and redacted.

Public diagnostics:

- typed Swift errors
- `NSError` domain and codes for Objective-C
- structured log events
- bounded in-memory log recorder
- redacted support report
- port latency reports with route, connect timing, SSH service timing, and total timing

Unexpected failures must surface. SSHKit avoids silent fallbacks, empty success values, and default data that hides broken state.

## Algorithm Profiles

`SSHAlgorithmProfile.modern` keeps libssh's modern defaults and sets the client RSA minimum to 3072 bits.
`SSHAlgorithmProfile.legacyRSA` explicitly opts into `ssh-rsa` host-key and public-key algorithms and lowers the RSA minimum to 1024 bits for legacy endpoints.
Custom profiles pass comma-separated libssh/OpenSSH algorithm lists directly to libssh. Lists may use libssh's OpenSSH-compatible `+`, `-`, and `^` modifiers.

libssh rejects unsupported algorithm names during session configuration and algorithm inspection. SSHKit exposes those failures as typed errors. Public-key accepted algorithms inherit libssh's host-key defaults when the profile leaves `publicKeyAcceptedAlgorithms` unset. libssh exposes RSA minimum size as a set-only option, so the snapshot reports the accepted configured value when a profile supplies one and leaves it absent for libssh defaults. SSHKit's algorithm support is bounded by the vendored libssh/OpenSSL build; endpoints that require algorithms outside that build need server-side configuration changes or a custom libssh build.

## Compatibility Target

SSHKit aims to cover the same application-level capability surface as modern Swift SSH libraries:

- connect and scoped connect
- authentication discovery
- password auth
- private-key auth
- keyboard-interactive auth
- SSH agent auth
- host trust store
- known hosts
- pinned host keys
- collected commands
- streamed commands
- PTY shells
- SFTP operations
- SCP helpers
- direct TCP channels
- local port forwarding
- remote port forwarding
- dynamic forwarding
- SOCKS and HTTP CONNECT proxy routes
- ProxyJump
- structured diagnostics
- algorithm profile inspection
- legacy RSA opt-in
- key generation helpers
- latency measurement tools

SSHKit exposes these capabilities through its own names and the blocking worker model described above.
