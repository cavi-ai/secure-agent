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

    static func supportsHook(_ harness: String) -> Bool { harness == "claude" || harness == "cursor" }

    var suggestedHarness: String {
        for candidates in [activeHarnesses, configuredHarnesses] {
            if candidates.contains("claude") { return "claude" }
            if candidates.contains("cursor") { return "cursor" }
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
