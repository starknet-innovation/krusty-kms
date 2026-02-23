// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "KrustyKms",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "KrustyKms", targets: ["KrustyKms"]),
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
            name: "KrustyKms",
            dependencies: ["CKms"],
            path: "Sources/KrustyKms"
        )
    ]
)
