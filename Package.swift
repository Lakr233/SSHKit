// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SSHKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .macCatalyst(.v16),
        .tvOS(.v16),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "SSHKit", type: .dynamic, targets: ["SSHKit"]),
        .library(name: "SSHKitObjC", type: .dynamic, targets: ["SSHKitObjC"]),
        .library(name: "CLibSSH", type: .dynamic, targets: ["CLibSSH"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Lakr233/openssl-spm.git", from: "3.6.0"),
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
                .define("SSHKit_CLibSSH_PLACEHOLDER", to: "1"),
            ],
            linkerSettings: [
                .linkedLibrary("z"),
            ]
        ),
        .target(
            name: "SSHKitObjC",
            dependencies: ["CLibSSH"],
            path: "Sources/SSHKitObjC",
            publicHeadersPath: "include"
        ),
        .target(
            name: "SSHKit",
            dependencies: ["SSHKitObjC"],
            path: "Sources/SSHKit",
            swiftSettings: [
                .swiftLanguageMode(.v5),
            ]
        ),
        .testTarget(
            name: "SSHKitTests",
            dependencies: ["SSHKit"]
        ),
    ],
    cLanguageStandard: .c11
)
