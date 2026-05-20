# SSHKit

Swift package for libssh on Apple platforms.

Products are dynamic libraries so LGPL library replacement stays explicit.

Current state: package skeleton with Swift facade, Objective-C thread-safety boundary, and placeholder `CLibSSH` target. The next step is wiring vendored libssh source into `CLibSSH`.
