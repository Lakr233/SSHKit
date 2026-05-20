# SSHKit Design

SSHKit follows the source-package shape used by `Lakr233/libssh2-spm`: upstream code lives under `Vendor`, C compile settings live in `Package.swift`, and Swift-friendly API lives in a separate target.

All public products are declared as dynamic libraries. This keeps the libssh boundary explicit for app packaging and LGPL compliance.

The intended layer split:

- `CLibSSH`: vendored libssh C source and generated config headers.
- `SSHKitObjC`: Objective-C owner for libssh handles, thread confinement, and `NSError` bridging.
- `SSHKit`: Swift API surface for app code.

`SSHKitObjC` is the synchronization boundary. Each `GSSHSession` owns a serial dispatch queue. Future `ssh_session`, `ssh_channel`, and `sftp_session` calls should run through that queue.

Crypto backend:

- Use `https://github.com/Lakr233/openssl-spm` for libssh's OpenSSL backend.
- Use Apple's Security framework for app-level trust/keychain work where needed.
- zlib is linked explicitly through the system `z` library.
