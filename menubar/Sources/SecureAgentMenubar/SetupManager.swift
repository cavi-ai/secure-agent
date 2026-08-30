import AppKit
import Foundation
import ServiceManagement

/// Owns first-run setup and teardown: harness hooks, login item, CLI symlink,
/// and Full Disk Access guidance. The daemon itself is not set up here — it is
/// a child process of the app (see `DaemonSupervisor`), not a LaunchAgent, so
/// it can never outlive the visible menu bar app.
@MainActor
public final class SetupManager: ObservableObject {
    public static let shared = SetupManager()

    public static let daemonLabel = "com.cavi-ai.secure-agentd"

    @Published public private(set) var isDaemonRunning = false
    @Published public private(set) var areHooksInstalled = false
    @Published public private(set) var lastError: String?

    private let fm = FileManager.default
    private let home = NSHomeDirectory()

    private var launchAgentsDir: String { "\(home)/Library/LaunchAgents" }
    /// Path of the legacy daemon LaunchAgent. Older versions installed a
    /// KeepAlive=true agent here that respawned the daemon behind the user's
    /// back; it is now migrated away on launch (see `migrateLegacyLaunchAgent`).
    private var daemonPlistPath: String { "\(launchAgentsDir)/\(Self.daemonLabel).plist" }

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
        let statusReachable = (try? await DaemonClient().fetchStatus().running) ?? false
        isDaemonRunning = DaemonSupervisor.shared.isRunning || statusReachable
        areHooksInstalled = Self.hookTargets.contains { target in
            fm.fileExists(atPath: "\(target)/secret_guard.py")
        }
    }

    /// The only mandatory setup step is installing the harness hooks; the daemon
    /// starts automatically with the app. FDA, login item, and the CLI are
    /// optional extras and do not force the wizard open.
    public var needsSetup: Bool {
        isBundled && !areHooksInstalled
    }

    // MARK: - Legacy LaunchAgent migration

    /// Remove the KeepAlive daemon LaunchAgent left by older versions. Those
    /// versions ran the daemon under launchd, so it respawned when killed and
    /// kept running after the menu bar app was quit. Now the app owns the
    /// daemon's lifetime directly, so any leftover agent must be torn down.
    public func migrateLegacyLaunchAgent() {
        guard fm.fileExists(atPath: daemonPlistPath) else { return }
        let uid = getuid()
        Self.run(["/bin/launchctl", "bootout", "gui/\(uid)/\(Self.daemonLabel)"])
        try? fm.removeItem(atPath: daemonPlistPath)
        NSLog("[secure-agent] removed legacy daemon LaunchAgent")
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

    // MARK: - Agent routing (opt-in proxy)

    /// The daemon writes this sourceable snippet on startup; the app only points
    /// the user at it. Sourcing it is the user's own opt-in — we never edit a
    /// shell rc or the system trust store.
    public var agentRoutingSnippetPath: String {
        "\(home)/.config/secure-agent/agent-env.sh"
    }

    public var isAgentRoutingConfigured: Bool {
        fm.fileExists(atPath: agentRoutingSnippetPath)
    }

    public var agentRoutingSourceCommand: String {
        "source ~/.config/secure-agent/agent-env.sh"
    }

    public func copyAgentRoutingCommand() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(agentRoutingSourceCommand, forType: .string)
    }

    public func revealAgentRoutingSnippet() {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: agentRoutingSnippetPath)])
    }

    // MARK: - Secret registry (fingerprints)

    @Published public private(set) var registeredSecrets: [String] = []
    @Published public private(set) var didRegisterSecrets = false

    /// Ask the daemon to scan the configured sources and register HMAC-only
    /// fingerprints of the user's secrets, activating the highest-precision
    /// detection layer. Never sees or stores plaintext.
    public func registerSecrets() async {
        lastError = nil
        do {
            registeredSecrets = try await DaemonClient().registerSecrets()
            didRegisterSecrets = true
        } catch {
            report(error)
        }
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
        // Stop the child daemon this app is running.
        DaemonSupervisor.shared.stop()
        // Tear down any legacy LaunchAgent from an older install.
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
