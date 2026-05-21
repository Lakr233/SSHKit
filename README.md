# SSHKit

Swift package for libssh on Apple platforms.

Products are dynamic libraries so LGPL library replacement stays explicit.

Current MVP capabilities:

- password, private-key-file, keyboard-interactive, agent, and generated-key authentication
- known-hosts files, pinned fingerprints, memory trust stores, and Keychain trust stores
- collected commands, streamed commands, PTY shells, exit status, and exit signal metadata
- SFTP directory, file, handle, upload, download, resume, symlink, and filesystem operations
- direct TCP channels, local forwarding, remote forwarding, dynamic SOCKS forwarding, SOCKS5 routes, HTTP CONNECT routes, and ProxyJump
- SCP single-file upload and download helpers
- structured logging, bounded log recorders, diagnostic reports, algorithm profiles, and latency probes

The live test suite targets an external Alpine SSH fixture. It covers real command, shell/PTY, SFTP list/upload/download, SCP, forwarding, proxy route, authentication failure, host-key failure, cancellation, and scoped connection behavior.

Validation entry points:

```sh
swiftformat Sources Tests --swiftversion 6.2
swift test
Script/test-destinations.sh
Script/test-live-fixture.sh
```

`Script/test-live-fixture.sh` requires the external fixture environment in `Documentation/Fixtures/AlpineSSH.md` and rejects loopback hosts.
