// swift-tools-version:5.9
// bridge-ios — local companion for the Android Bridge service
import PackageDescription

let package = Package(
    name: "BridgeIOS",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "BridgeKit", targets: ["BridgeKit"]),
    ],
    targets: [
        .target(
            name: "BridgeKit",
            path: "Sources/BridgeKit"
        ),
        .testTarget(
            name: "BridgeKitTests",
            dependencies: ["BridgeKit"],
            path: "Tests/BridgeKitTests"
        ),
    ]
)
