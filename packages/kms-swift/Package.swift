// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "GhoulKms",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "GhoulKms", targets: ["GhoulKms"]),
    ],
    targets: [
        .target(
            name: "CKms",
            path: "Sources/CKms",
            sources: ["empty.c"],
            publicHeadersPath: "include",
            linkerSettings: [
                .unsafeFlags(["-lkms"])
            ]
        ),
        .target(
            name: "GhoulKms",
            dependencies: ["CKms"],
            path: "Sources/GhoulKms"
        )
    ]
)
