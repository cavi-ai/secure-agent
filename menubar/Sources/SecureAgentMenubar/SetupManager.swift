import AppKit
import Foundation
import ServiceManagement

/// Owns first-run setup and teardown: daemon LaunchAgent, harness hooks,
/// login item, CLI symlink, and Full Disk Access guidance.
@MainActor
public final class SetupManager: ObservableObject {
    public static let shared = SetupManager()

    public static let daemonLabel = "com.cavi-ai.secure-agentd"

    @Published public private(set) var isDaemonInstalled = false
    @Published public private(set) var isDaemonRunning = false
    @Published public private(set) var areHooksInstalled = false
    @Published public private(set) var lastError: String?

    private let fm = FileManager.default
    private let home = NSHomeDirectory()

    private var launchAgentsDir: String { "\(home)/Library/LaunchAgents" }
    private var daemonPlistPath: String { "\(launchAgentsDir)/\(Self.daemonLabel).plist" }
    private var logsDir: String { "\(home)/Library/Logs/secure-agent" }

    /// Path to the daemon inside the app bundle. Nil when running unbundled
    /// (e.g. `swift run` during development).
    public var bundledDaemonPath: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/secure-agentd").path
        return fm.fileExists(atPath: path) ? path : nil
    }

    public var bundledCLIPath: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/secure-agent").path
        return fm.fileExists(atPath: path) ? path : nil
    }

    private var bundledHooksDir: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Resources/hooks").path
        return fm.fileExists(atPath: path) ? path : nil
    }

    public var isBundled: Bool { bundledDaemonPath != nil }

    private init() {}

    // MARK: - State

    public func refreshState() async {
        isDaemonInstalled = fm.fileExists(atPath: daemonPlistPath)
        isDaemonRunning = (try? await DaemonClient().fetchStatus().running) ?? false
        areHooksInstalled = Self.hookTargets.contains { target in
            fm.fileExists(atPath: "\(target)/secret_guard.py")
        }
    }

    public var needsSetup: Bool {
        !isDaemonInstalled || !isDaemonRunning
    }

    // MARK: - Daemon LaunchAgent

    public func installDaemon() throws {
        guard let daemonPath = bundledDaemonPath else {
            throw SetupError.notBundled
        }
        lastError = nil
        try fm.createDirectory(atPath: launchAgentsDir, withIntermediateDirectories: true)
        try fm.createDirectory(atPath: logsDir, withIntermediateDirectories: true)

        let plist: [String: Any] = [
            "Label": Self.daemonLabel,
            "ProgramArguments": [daemonPath],
            "RunAtLoad": true,
            "KeepAlive": true,
            "StandardOutPath": "\(logsDir)/daemon.log",
            "StandardErrorPath": "\(logsDir)/daemon-err.log",
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: URL(fileURLWithPath: daemonPlistPath), options: .atomic)

        let uid = getuid()
        // Ignore failures here: bootout fails when the service isn't loaded yet.
        Self.run(["/bin/launchctl", "bootout", "gui/\(uid)/\(Self.daemonLabel)"])
        let boot = Self.run(["/bin/launchctl", "bootstrap", "gui/\(uid)", daemonPlistPath])
        if boot != 0 {
            // Already registered from an older install: reload it.
            Self.run(["/bin/launchctl", "kickstart", "-k", "gui/\(uid)/\(Self.daemonLabel)"])
        }
    }

    // MARK: - Harness hooks

    public static let hookTargets: [String] = [
        NSHomeDirectory() + "/.claude/hooks",
        NSHomeDirectory() + "/.cursor/hooks",
        NSHomeDirectory() + "/.config/opencode/hooks",
    ]

    public func installHooks() throws {
        guard let srcDir = bundledHooksDir else { throw SetupError.notBundled }
        lastError = nil
        let hooks = try fm.contentsOfDirectory(atPath: srcDir)
            .filter { $0.hasSuffix(".py") && !$0.hasPrefix("test_") }
        for target in Self.hookTargets {
            try fm.createDirectory(atPath: target, withIntermediateDirectories: true)
            for hook in hooks {
                let dst = "\(target)/\(hook)"
                if fm.fileExists(atPath: dst) { try fm.removeItem(atPath: dst) }
                try fm.copyItem(atPath: "\(srcDir)/\(hook)", toPath: dst)
            }
        }
    }

    // MARK: - Login item

    public func enableLoginItem() throws {
        lastError = nil
        if SMAppService.mainApp.status != .enabled {
            try SMAppService.mainApp.register()
        }
    }

    public var isLoginItemEnabled: Bool {
        SMAppService.mainApp.status == .enabled
    }

    // MARK: - CLI symlink

    public func installCLI() throws {
        guard let cliPath = bundledCLIPath else { throw SetupError.notBundled }
        lastError = nil
        let binDir = "\(home)/.local/bin"
        try fm.createDirectory(atPath: binDir, withIntermediateDirectories: true)
        let link = "\(binDir)/secure-agent"
        if fm.fileExists(atPath: link) { try fm.removeItem(atPath: link) }
        try fm.createSymbolicLink(atPath: link, withDestinationPath: cliPath)
    }

    // MARK: - Full Disk Access

    public func openFullDiskAccessSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: - Uninstall

    public func uninstallAll() throws {
        lastError = nil
        let uid = getuid()
        Self.run(["/bin/launchctl", "bootout", "gui/\(uid)/\(Self.daemonLabel)"])
        if fm.fileExists(atPath: daemonPlistPath) {
            try fm.removeItem(atPath: daemonPlistPath)
        }
        if SMAppService.mainApp.status == .enabled {
            try? SMAppService.mainApp.unregister()
        }
        for target in Self.hookTargets {
            for hook in ["secret_guard.py", "injection_scan.py", "activity_log.py"] {
                try? fm.removeItem(atPath: "\(target)/\(hook)")
            }
        }
        try? fm.removeItem(atPath: "\(home)/.local/bin/secure-agent")
    }

    // MARK: - Helpers

    @discardableResult
    private static func run(_ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: args[0])
        p.arguments = Array(args.dropFirst())
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus
        } catch {
            return -1
        }
    }

    public func report(_ error: Error) {
        lastError = error.localizedDescription
    }

    public enum SetupError: LocalizedError {
        case notBundled

        public var errorDescription: String? {
            switch self {
            case .notBundled:
                return "This copy of Secure Agent is not running from its app bundle. Drag Secure Agent.app to /Applications and relaunch it."
            }
        }
    }
}
