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

    static let hookHarnesses = ["claude", "cursor", "codex", "openclaw"]
    static func supportsHook(_ harness: String) -> Bool { hookHarnesses.contains(harness) }
    static func supportsProbe(_ harness: String) -> Bool { harness == "claude" || harness == "cursor" }

    static func activationGuidance(_ harness: String) -> String {
        switch harness {
        case "codex": return "Open /hooks in Codex, review and trust the Secure Agent hooks, then start a new session. Codex can disable hooks in its configuration. Registration does not prove invocation."
        case "openclaw": return "Restart the OpenClaw Gateway after registration. The Secure Agent plugin must remain enabled by OpenClaw policy. Guard approvals expire after five seconds so the check finishes within OpenClaw's hook timeout. Registration does not prove invocation."
        default: return "Run the manual hook check, then start a new agent session."
        }
    }

    var suggestedHarness: String {
        for candidates in [activeHarnesses, configuredHarnesses] {
            if let harness = Self.hookHarnesses.first(where: { candidates.contains($0) }) { return harness }
        }
        return "claude"
    }

    func receipt(for harness: String) -> CoverageProbeReceiptModel? { probes.first { $0.harness == harness } }

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
            return Result(title: "Hook check not run", detail: "Installation alone does not establish that the hook reaches the monitor. Run the manual check when ready.")
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
    init(stage: FirstUseSetupStage = .choose, selectedHarness: String = "claude") {
        self.stage = stage
        self.selectedHarness = selectedHarness
    }
}

enum FileTelemetryPermissionGuidance {
    static let instruction = "Turn on Secure Agent in System Settings → Privacy & Security → Full Disk Access. macOS attributes the bundled file-telemetry service to this app."
}
