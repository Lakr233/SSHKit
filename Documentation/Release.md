# Release Process

SSHKit releases are produced from a clean git checkout.

## Validation

Run the full local validation suite:

```sh
swiftformat Sources Tests --swiftversion 6.2
swift test
Script/test-destinations.sh
```

Run live fixture tests with the external fixture environment described in `Documentation/Fixtures/AlpineSSH.md`:

```sh
Script/test-live-fixture.sh
```

## Packaging

Create release artifacts from the commit being released:

```sh
Script/package-release.sh <version>
```

The script resolves dependencies, builds the package in release mode, writes a source archive, exports package metadata, and records SHA-256 checksums under `.build/release-artifacts`.

## CI

`.github/workflows/ci.yml` runs `Script/test-destinations.sh` on pull requests and pushes to `main` or `codex/**` branches. That script runs SwiftPM tests on macOS and builds the supported Apple destinations available to the selected Xcode runner: iOS, macOS, Mac Catalyst, tvOS, and visionOS.
