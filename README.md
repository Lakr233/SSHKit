# SSHKit

Swift Package wrapping [libssh](https://www.libssh.org/) for Apple platforms.
SSHKit provides async/await, callback, and Objective-C APIs for embedding SSH
client features in Apple apps. It ships `SSHKit`, `SSHKitObjC`, and `CLibSSH`
as dynamic library products so the LGPL boundary remains explicit.

## Platforms

iOS 13+, macOS 10.15+, Mac Catalyst 13+, tvOS 13+, visionOS 1+.
watchOS is not supported.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/Lakr233/SSHKit.git", from: "0.1.6"),
]
```

Add `.product(name: "SSHKit", package: "SSHKit")` to your target.

## Quick Start

```swift
import SSHKit

let config = SSHClient.Configuration(
    host: "example.com",
    username: "deploy",
    authentication: .password("secret"),
    hostKeyPolicy: .knownHostsFile("/Users/me/.ssh/known_hosts")
)

let result = try await SSHClient.withConnection(config) {
    try await $0.execute("uname -a")
}
print(String(decoding: result.standardOutput, as: UTF8.self))
```

## Features

- Password, private-key-file, keyboard-interactive, and SSH agent authentication.
- Known-hosts files, pinned fingerprints, memory trust stores, and Keychain trust stores.
- Commands, PTY shells, SFTP, SCP, port forwarding, ProxyJump, and diagnostics.
- Modern algorithm defaults with an opt-in legacy RSA profile.

One `SSHConnection` runs one active high-level job at a time. Use more
connections for concurrent work, and reserve `.insecureAcceptAnyHostKey` for
disposable development fixtures.

## Documentation

Full guide, API notes, architecture overview, and Objective-C usage:
[SSHKit on GitHub Pages](https://lakr233.github.io/SSHKit/).

The sample app in `Example/SSHKitExample.xcodeproj` covers the main workflows.

## License

SSHKit project code is MIT licensed. See [LICENSE](LICENSE). Vendored libssh
code under `Vendor/libssh` remains under upstream GNU LGPL terms. Third-party
dependencies retain their own licenses; see [NOTICE](NOTICE).
