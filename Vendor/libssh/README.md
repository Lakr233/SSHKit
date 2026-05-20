# libssh Vendor Source

This directory is reserved for libssh `0.12.x` source.

Planned integration:

- copy upstream `include/libssh` and selected `src` files here
- generate `libssh_version.h` and config headers for Apple platforms
- enable OpenSSL, zlib, SFTP, GEX, and client APIs
- keep server APIs as an explicit product decision
- exclude upstream examples, tests, and build-system files from the target
