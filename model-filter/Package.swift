// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ModelFilter",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "ModelFilterCore", targets: ["ModelFilterCore"]),
        .executable(name: "secure-agent-model-filter", targets: ["ModelFilterProvider"])
    ],
    targets: [
        .target(name: "ModelFilterCore"),
        .target(name: "ModelFilterCompat", cSettings: [.unsafeFlags(["-fobjc-arc"])]),
        .executableTarget(name: "ModelFilterProvider", dependencies: ["ModelFilterCore", "ModelFilterCompat"]),
        .testTarget(name: "ModelFilterCoreTests", dependencies: ["ModelFilterCore"])
    ]
)
