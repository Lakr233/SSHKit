// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SSHKit",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .macCatalyst(.v13),
        .tvOS(.v13),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "SSHKit", type: .dynamic, targets: ["SSHKit"]),
        .library(name: "SSHKitObjC", type: .dynamic, targets: ["SSHKitObjC"]),
        .library(name: "CLibSSH", type: .dynamic, targets: ["CLibSSH"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Lakr233/openssl-spm.git", from: "3.6.0"),
        .package(url: "https://github.com/kishikawakatsumi/KeychainAccess.git", from: "4.2.2"),
    ],
    targets: [
        .target(
            name: "CLibSSH",
            dependencies: [
                .product(name: "OpenSSL", package: "openssl-spm"),
            ],
            path: "Sources/CLibSSH",
            publicHeadersPath: "include",
            cSettings: [
                .define("SSHKIT_CLIBSSH_PLACEHOLDER", to: "1"),
            ],
            linkerSettings: [
                .linkedLibrary("z"),
            ],
        ),
        .target(
            name: "SSHKitObjC",
            dependencies: ["CLibSSH"],
            path: "Sources/SSHKitObjC",
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("Private"),
            ],
        ),
        .target(
            name: "SSHKit",
            dependencies: [
                "SSHKitObjC",
                .product(name: "KeychainAccess", package: "KeychainAccess"),
            ],
            path: "Sources/SSHKit",
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ],
        ),
        .testTarget(
            name: "SSHCoreObjCTests",
            dependencies: ["SSHKitObjC"],
            path: "Tests/SSHCoreObjCTests",
            cSettings: [
                .headerSearchPath("../../Sources/SSHKitObjC/Private"),
            ],
        ),
        .testTarget(
            name: "SSHKitTests",
            dependencies: ["SSHKit"],
        ),
        .testTarget(
            name: "LiveSSHTests",
            dependencies: ["SSHKit"],
        ),
    ],
    cLanguageStandard: .c11,
)
