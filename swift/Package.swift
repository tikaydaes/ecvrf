// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ECVRF",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ECVRF", targets: ["ECVRF"]),
        .executable(name: "ecvrf-test", targets: ["ECVRFTest"]),
        .executable(name: "ecvrf-cli", targets: ["ECVRFCli"]),
    ],
    targets: [
        .target(
            name: "ECVRF",
            dependencies: []
        ),
        .executableTarget(
            name: "ECVRFTest",
            dependencies: ["ECVRF"]
        ),
        .executableTarget(
            name: "ECVRFCli",
            dependencies: ["ECVRF"]
        ),
    ]
)
