// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecureAgentInstaller",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "secure-agent-installer", targets: ["SecureAgentInstaller"])
    ],
    targets: [
        .executableTarget(
            name: "SecureAgentInstaller",
            path: "Sources/SecureAgentInstaller"
        )
    ]
)
