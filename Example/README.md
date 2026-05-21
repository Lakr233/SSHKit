# SSHKitExample

A sample iOS / macOS / Mac Catalyst app that exercises SSHKit's public Swift API.
The interactive terminal uses [libghostty-spm](https://github.com/Lakr233/libghostty-spm)
in its "feed remote bytes" mode (`InMemoryTerminalSession`) instead of
spawning a local PTY.

## What it covers

| Screen          | SSHKit surface                                            |
| --------------- | --------------------------------------------------------- |
| Command         | `connection.execute(_:)` and `connection.openCommand(_:)` (collected + streamed modes) |
| Terminal        | `connection.openShell(...)` + `SSHShell.write/resize/close` ↔ `InMemoryTerminalSession.receive(_:)` |
| SFTP            | `connection.openSFTP()` + `SFTPClient.upload/download/list/remove/rename` |
| Port Map        | `startLocalForward` / `startRemoteForward` / `startDynamicForward`        |
| Multi-Command   | N concurrent `SSHClient.withConnection(configuration) { ... }`            |
| Session Fuzz    | Loop of `execute` calls per worker, one connection per worker             |
| Latency Probe   | `SSHPortLatencyProbe.measure(configuration:)`                             |

Host-key enrollment uses `SSHClient.discoverHostKey(configuration:)` to learn
the fingerprint without authenticating, presents an approval sheet, and saves
the trusted fingerprint to the Keychain (`service: "wiki.qaq.sshkit"`). All
subsequent connects use `SSHHostKeyPolicy.trustStore(...)`.

## Platforms

- iOS 26
- macOS 26
- Mac Catalyst 26

visionOS is intentionally not supported (libghostty-spm doesn't declare it).

## Running

Open `Example/SSHKitExample.xcodeproj` in Xcode 26 or later. The Swift Package
references resolve automatically:

- SSHKit (this repo, via `XCLocalSwiftPackageReference relativePath = ..`)
- libghostty-spm 1.1.5+

Default credentials in `SetupConnectionView` point at the local Alpine fixture
described in `../Documentation/Fixtures/AlpineSSH.md` (`127.0.0.1:7422`,
`root`). Override before connecting if your fixture differs.

### Tests

```sh
Script/test-example.sh             # runs macOS + iOS Sim + Mac Catalyst
Script/test-example.sh macos       # subset
Script/test-example.sh ios         # subset
Script/test-example.sh catalyst    # subset
```

Unit tests use Swift Testing and do not hit the network. The UI smoke test
launches the app and verifies the root accessibility identifier; it does not
walk the sidebar (iPhone collapses `NavigationSplitView` in compact width).

Live coverage continues to live in the `LiveSSHTests` target under
`swift test` at the repo root.

## Binary dependency compatibility

The example app pins its package graph to OpenSSL 4.0.0 and libghostty-spm
1.1.5 or newer. Those releases keep the XCFramework module maps inside their
own framework bundles, so Xcode can process both binary dependencies in the
same build.

## Code-signing

Defaults in the .pbxproj are ad-hoc (`CODE_SIGN_IDENTITY = -`,
`CODE_SIGN_STYLE = Manual`, empty `DEVELOPMENT_TEAM`) so CI builds without a
developer team. macOS and Catalyst keep signing enabled so the App Sandbox /
network / user-selected-file entitlements actually load. iOS Simulator builds
unsigned because the simulator doesn't enforce entitlements.

If you want Developer ID / TestFlight signing locally, override
`DEVELOPMENT_TEAM` and switch `CODE_SIGN_STYLE` to `Automatic` via an
xcconfig or in Xcode's Signing & Capabilities pane.

## What's not covered

These SSHKit public APIs are deliberately out of scope for v1 of the sample
so the surface stays focused:

- SCP single-file transfers (`SCPClient`)
- Agent / keyboard-interactive / private-key authentication
- Authentication-method discovery (`SSHClient.discoverAuthenticationMethods`)
- Key generation (`SSHKeyGenerator`)
- Direct TCP channels (`connection.openDirectTCPChannel`)
- Proxy routes (SOCKS5, HTTP CONNECT, ProxyJump)
- Custom algorithm profiles beyond `.modern`

Add them when the basic flows are stable.
