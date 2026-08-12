// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecureAgentMenubar",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "secure-agent-menubar", targets: ["SecureAgentMenubar"])
    ],
    targets: [
        .executableTarget(
            name: "SecureAgentMenubar",
            path: "Sources/SecureAgentMenubar"
        ),
        .testTarget(
            name: "SecureAgentMenubarTests",
            dependencies: ["SecureAgentMenubar"],
            path: "Tests/SecureAgentMenubarTests"
        )
    ]
)
