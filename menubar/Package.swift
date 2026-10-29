// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecureAgentMenubar",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "secure-agent-menubar", targets: ["SecureAgentMenubar"]),
        .executable(name: "secure-agent-image-text", targets: ["ImageText"])
    ],
    targets: [
        .executableTarget(
            name: "SecureAgentMenubar",
            path: "Sources/SecureAgentMenubar"
        ),
        .target(
            name: "ImageTextCore",
            path: "Sources/ImageTextCore"
        ),
        .executableTarget(
            name: "ImageText",
            dependencies: ["ImageTextCore"],
            path: "Sources/ImageText"
        ),
        .testTarget(
            name: "SecureAgentMenubarTests",
            dependencies: ["SecureAgentMenubar"],
            path: "Tests/SecureAgentMenubarTests"
        ),
        .testTarget(
            name: "ImageTextTests",
            dependencies: ["ImageTextCore"],
            path: "Tests/ImageTextTests"
        )
    ]
)
