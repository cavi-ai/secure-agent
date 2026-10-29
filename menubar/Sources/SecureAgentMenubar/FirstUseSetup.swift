import Foundation
import Combine

/// Installation, a manual probe, and session observations remain independent.
/// The daemon owns probe applicability and all session coverage states.
struct FirstUseSetupState {
    var daemonAvailable = false
    var installedHarnesses: Set<String> = []
    var configuredHarnesses: Set<String> = []
    var activeHarnesses: Set<String> = []
    var probes: [CoverageProbeReceiptModel] = []
    var sessions: [SessionCoverageModel] = []
    var sessionsUnavailable = false
    var sessionsTruncated = false

    static let sampleTask = "List this project's files and summarize its README. Do not change files, read secrets, or contact external services."

    func sessionDestination(for session: SessionCoverageModel, harness: String) -> ConsoleDestination? {
        guard daemonAvailable, !sessionsUnavailable, session.harness == harness,
              let id = session.sessionID, !id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              sessions.contains(where: { $0.sessionID == id && $0.harness == harness }) else { return nil }
        return .session(id)
    }

    static let hookHarnesses = ["claude", "cursor", "codex", "openclaw", "antigravity", "hermes", "opencode"]
    static func supportsHook(_ harness: String) -> Bool { hookHarnesses.contains(harness) }
    static func supportsProbe(_ harness: String) -> Bool { harness == "claude" || harness == "cursor" }

    static func activationGuidance(_ harness: String) -> String {
        switch harness {
        case "codex": return "Approve the new hooks in Codex, then start a new session."
        case "openclaw": return "Restart the Gateway to activate the plugin."
        case "antigravity": return "New Antigravity sessions load the hooks."
        case "hermes": return "Restart Hermes to load the plugin."
        case "opencode": return "Restart OpenCode to load the plugin."
        default: return "Start a new session after setup."
        }
    }

    static func installationDetail(_ harness: String) -> String {
        "Enable Secure Agent hooks for \(harness). Existing settings are preserved."
    }

    var suggestedHarness: String {
        for candidates in [activeHarnesses, configuredHarnesses] {
            if let harness = Self.hookHarnesses.first(where: { candidates.contains($0) }) { return harness }
        }
        return "claude"
    }

    func receipt(for harness: String) -> CoverageProbeReceiptModel? { probes.first { $0.harness == harness } }

    func installationStatus(for harness: String) -> String {
        guard installedHarnesses.contains(harness) else { return "Hooks not installed" }
        if harness == "openclaw" { return "Plugin files installed" }
        return Self.supportsProbe(harness) ? "Hooks installed and registered" : "Hooks registered; activation required"
    }

    struct Result {
        let title: String
        let detail: String
        var passed = false
    }

    func result(for harness: String) -> Result {
        guard daemonAvailable else {
            return Result(title: "Monitor status unavailable", detail: "Recheck the monitor before relying on earlier setup results.")
        }
        guard Self.supportsHook(harness) else {
            return Result(title: "Observation path selected", detail: "This harness has no supported interactive guard hook. Recorded session activity can still be inspected when available.")
        }
        guard installedHarnesses.contains(harness) else {
            return Result(title: "Hooks not installed", detail: "The selected harness needs its hook scripts and registration. Other harnesses do not need to be configured.")
        }
        if !Self.supportsProbe(harness) {
            return Result(title: "Hook activation required", detail: Self.activationGuidance(harness))
        }
        guard let receipt = receipt(for: harness) else {
            return Result(title: "Hooks configured", detail: "Start a new agent session. Connection checks are available under Diagnostics.")
        }
        switch receipt.state {
        case "passed": return Result(title: "Installed hook check passed", detail: receipt.detail, passed: true)
        case "changed": return Result(title: "Hook configuration changed", detail: receipt.detail)
        case "expired": return Result(title: "Hook check expired", detail: receipt.detail)
        case "failed": return Result(title: "Hook check failed", detail: receipt.detail)
        default: return Result(title: "Hook result unavailable", detail: "The monitor returned an unrecognized check state. Refresh or update Secure Agent before relying on it.")
        }
    }
}

enum FirstUseSetupStage { case choose, enable, result }

@MainActor
final class FirstUseSetupFlow: ObservableObject {
    @Published var stage: FirstUseSetupStage
    @Published var selectedHarness: String
    @Published private(set) var installing = false
    private var suggestsHarness: Bool

    init(stage: FirstUseSetupStage = .choose, selectedHarness: String? = nil) {
        self.stage = stage
        self.selectedHarness = selectedHarness ?? "claude"
        suggestsHarness = selectedHarness == nil
    }

    func applySuggestedHarness(_ harness: String) {
        guard suggestsHarness else { return }
        selectedHarness = harness
        suggestsHarness = false
    }

    func selectHarness(_ harness: String) {
        guard !installing else { return }
        selectedHarness = harness
        suggestsHarness = false
    }

    func beginSetup(for harness: String) {
        guard !installing else { return }
        selectHarness(harness)
        stage = .enable
    }

    func install(using setup: SetupManager) async {
        guard !installing else { return }
        installing = true
        let harness = selectedHarness
        defer { installing = false }
        do {
            try await setup.configureHooks(for: harness)
            if FirstUseSetupState.supportsProbe(harness) { await setup.refreshState() }
            stage = .result
        } catch { setup.report(error) }
    }
}

enum FileTelemetryPermissionGuidance {
    static let instruction = "Turn on Secure Agent in System Settings → Privacy & Security → Full Disk Access. macOS attributes the bundled file-telemetry service to this app."
}
