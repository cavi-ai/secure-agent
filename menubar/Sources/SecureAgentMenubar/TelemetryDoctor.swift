import Foundation
import ServiceManagement

// MARK: - Autopilot

/// A System Settings pane the file-telemetry autopilot opens at most once
/// per build.
enum ESSettingsPane: String, CaseIterable, Sendable {
    case loginItems, fullDiskAccess
}

/// The autopilot's next step for the file-telemetry service.
enum ESAutopilotAction: Equatable, Sendable {
    case none
    case register
    case open(ESSettingsPane)
}

/// Turns file telemetry on without a click: registers the service once per
/// launch, then opens each System Settings pane the user has to flip, once
/// per build. The user's Remove wins over all of it.
enum ESAutopilot {
    static func decide(stage: ESStage, userDisabled: Bool, attemptedThisLaunch: Bool,
                       panesOpenedForBuild: Set<ESSettingsPane>) -> ESAutopilotAction {
        if userDisabled { return .none }
        switch stage {
        case .notRegistered:
            return attemptedThisLaunch ? .none : .register
        case .requiresApproval:
            return panesOpenedForBuild.contains(.loginItems) ? .none : .open(.loginItems)
        case .needsGrant, .needsRegrant:
            return panesOpenedForBuild.contains(.fullDiskAccess) ? .none : .open(.fullDiskAccess)
        case .legacyInstalled, .notFound, .active:
            return .none
        }
    }
}

/// The autopilot's persisted flags: `userDisabled` (set by the card's Remove,
/// cleared by Enable) and, per pane, the CFBundleVersion it was last opened for.
struct ESAutopilotMemory {
    static let userDisabledKey = "esTelemetryUserDisabled"
    static func paneKey(_ pane: ESSettingsPane) -> String { "esTelemetryPaneOpenedBuild.\(pane.rawValue)" }

    let defaults: UserDefaults
    let build: String

    var userDisabled: Bool {
        get { defaults.bool(forKey: Self.userDisabledKey) }
        nonmutating set { defaults.set(newValue, forKey: Self.userDisabledKey) }
    }

    var panesOpenedForBuild: Set<ESSettingsPane> {
        Set(ESSettingsPane.allCases.filter { defaults.string(forKey: Self.paneKey($0)) == build })
    }

    func markOpened(_ pane: ESSettingsPane) {
        defaults.set(build, forKey: Self.paneKey(pane))
    }
}

/// The registration calls SetupManager makes on the collector service; a seam
/// so tests never register a real service.
protocol ESServiceControl {
    var status: SMAppService.Status { get }
    func register() throws
    func unregister() throws
}

extension SMAppService: ESServiceControl {}

// MARK: - Doctor model

enum DoctorState: String, Sendable {
    case pass, warn, fail

    var icon: String {
        switch self {
        case .pass: return "checkmark.circle.fill"
        case .warn: return "exclamationmark.triangle.fill"
        case .fail: return "xmark.octagon.fill"
        }
    }
}

enum DoctorFix: String, CaseIterable, Sendable {
    case register, reregister, openLoginItems, openFullDiskAccess, setAsideSpool, removeLegacy

    var title: String {
        switch self {
        case .register: return "Register"
        case .reregister: return "Re-register"
        case .openLoginItems: return "Open Login Items"
        case .openFullDiskAccess: return "Open Full Disk Access"
        case .setAsideSpool: return "Set spool aside"
        case .removeLegacy: return "Remove old helper"
        }
    }

    /// Fixes that finish only when the user flips a switch in System Settings.
    var needsUser: Bool { self == .openLoginItems || self == .openFullDiskAccess }
}

struct DoctorCheck: Identifiable, Equatable, Sendable {
    let id: String
    let title: String
    let state: DoctorState
    let cause: String
    let fix: DoctorFix?
}

/// `codesign -dv` facts for one signed file.
struct CodeSignature: Equatable, Sendable {
    var identifier: String
    var adhoc: Bool
    var teamIdentifier: String?

    /// Parses `codesign -dv` output (it prints to stderr); nil when no
    /// Identifier line is present (unsigned, or codesign failed).
    static func parse(_ output: String) -> CodeSignature? {
        var identifier: String?
        var adhoc = false
        var team: String?
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Identifier=") {
                identifier = String(line.dropFirst("Identifier=".count))
            } else if line == "Signature=adhoc" {
                adhoc = true
            } else if line.hasPrefix("TeamIdentifier=") {
                let value = String(line.dropFirst("TeamIdentifier=".count))
                team = value == "not set" ? nil : value
            }
        }
        guard let identifier, !identifier.isEmpty else { return nil }
        return CodeSignature(identifier: identifier, adhoc: adhoc, teamIdentifier: team)
    }
}

/// `launchctl print system/<label>` facts.
enum LaunchdProbe: Equatable, Sendable {
    case notFound
    case loaded(state: String, pid: Int?, lastExitCode: String?)
    case unreadable

    /// Reads the top-level (one tab deep) `state`, `pid` and `last exit code`
    /// lines; nested dictionaries repeat some keys and are skipped.
    static func parse(_ output: String) -> LaunchdProbe {
        if output.contains("Could not find service") { return .notFound }
        var state: String?
        var pid: Int?
        var lastExit: String?
        for raw in output.split(whereSeparator: \.isNewline) {
            let line = String(raw)
            guard line.hasPrefix("\t"), !line.hasPrefix("\t\t") else { continue }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if state == nil, trimmed.hasPrefix("state = ") {
                state = String(trimmed.dropFirst("state = ".count))
            } else if pid == nil, trimmed.hasPrefix("pid = ") {
                pid = Int(trimmed.dropFirst("pid = ".count))
            } else if lastExit == nil, trimmed.hasPrefix("last exit code = ") {
                lastExit = String(trimmed.dropFirst("last exit code = ".count))
            }
        }
        guard let state else { return .unreadable }
        return .loaded(state: state, pid: pid, lastExitCode: lastExit)
    }
}

/// Everything the Doctor evaluates, collected by SetupManager.
struct TelemetryFacts: Sendable {
    var now: Date
    var appSignature: CodeSignature?
    var helperSignature: CodeSignature?
    var plistPresent: Bool
    var serviceStatus: SMAppService.Status
    var launchd: LaunchdProbe
    /// Last non-empty line of the helper's log; nil when unreadable.
    var helperLogLastLine: String?
    /// The spool's mtime as this app sees it; nil when absent.
    var spoolMtime: Date?
    /// The daemon's `/status` `es_service`; nil when the daemon did not answer.
    var esService: ESServiceSnapshotModel?
    var legacyInstalled: Bool
    /// The daemon's `/doctor` checks; nil when the daemon did not answer.
    var daemonChecks: [DaemonDoctorCheckModel]?
}

// MARK: - Doctor

enum TelemetryDoctor {
    /// Running job, silent spool: longer than this means no Full Disk Access.
    static let grantStaleAfter: TimeInterval = 90
    /// Mostly unparsed spool that has not been written for this long is set aside.
    static let corruptStaleAfter: TimeInterval = 600
    static let adhocCause = "grants reset on every rebuild; build with make install on a Mac with an Apple Development identity"

    static func evaluate(_ f: TelemetryFacts) -> [DoctorCheck] {
        [signature(f), plist(f), registration(f), loginItems(f), launchdJob(f),
         fullDiskAccess(f), spoolHealth(f), legacyHelper(f)] + daemonChecks(f)
    }

    static func signature(_ f: TelemetryFacts) -> DoctorCheck {
        let title = "Code signature"
        guard let app = f.appSignature, let helper = f.helperSignature else {
            return DoctorCheck(id: "signature", title: title, state: .warn,
                               cause: "codesign could not read the app's or the helper's signature", fix: nil)
        }
        if helper.identifier != SetupManager.esCollectorLabel {
            return DoctorCheck(id: "signature", title: title, state: .fail,
                               cause: "the helper is signed as \(helper.identifier), not \(SetupManager.esCollectorLabel); rebuild the app",
                               fix: nil)
        }
        if app.adhoc || helper.adhoc {
            return DoctorCheck(id: "signature", title: title, state: .warn, cause: adhocCause, fix: nil)
        }
        return DoctorCheck(id: "signature", title: title, state: .pass,
                           cause: "signed by team \(app.teamIdentifier ?? "unknown")", fix: nil)
    }

    static func plist(_ f: TelemetryFacts) -> DoctorCheck {
        f.plistPresent
            ? DoctorCheck(id: "plist", title: "Service in the app", state: .pass,
                          cause: "the file-telemetry service's plist is in the app bundle", fix: nil)
            : DoctorCheck(id: "plist", title: "Service in the app", state: .fail,
                          cause: "this build has no \(SetupManager.esCollectorPlistName); rebuild the app", fix: nil)
    }

    static func registration(_ f: TelemetryFacts) -> DoctorCheck {
        let title = "Registration"
        switch f.serviceStatus {
        case .enabled, .requiresApproval:
            return DoctorCheck(id: "registration", title: title, state: .pass,
                               cause: "registered with macOS", fix: nil)
        default:
            return DoctorCheck(id: "registration", title: title, state: .fail,
                               cause: "macOS has no registration for the file-telemetry service",
                               fix: f.plistPresent ? .register : nil)
        }
    }

    static func loginItems(_ f: TelemetryFacts) -> DoctorCheck {
        let title = "Login Items approval"
        switch f.serviceStatus {
        case .enabled:
            return DoctorCheck(id: "login-items", title: title, state: .pass,
                               cause: "allowed in Login Items", fix: nil)
        case .requiresApproval:
            return DoctorCheck(id: "login-items", title: title, state: .fail,
                               cause: "waits for its switch under Secure Agent in Login Items", fix: .openLoginItems)
        default:
            return DoctorCheck(id: "login-items", title: title, state: .warn,
                               cause: "waits on registration", fix: nil)
        }
    }

    static func launchdJob(_ f: TelemetryFacts) -> DoctorCheck {
        let title = "launchd job"
        let enabled = f.serviceStatus == .enabled
        switch f.launchd {
        case .notFound:
            if enabled {
                return DoctorCheck(id: "launchd", title: title, state: .fail,
                                   cause: "the service is enabled but launchd has no job for it", fix: .reregister)
            }
            return DoctorCheck(id: "launchd", title: title, state: .warn,
                               cause: "no job yet; waits on registration and Login Items approval", fix: nil)
        case let .loaded(state, pid, lastExit):
            let exitNote = lastExit.map { ", last exit code \($0)" } ?? ""
            if let pid {
                return DoctorCheck(id: "launchd", title: title, state: .pass,
                                   cause: "\(state), pid \(pid)\(exitNote)", fix: nil)
            }
            return DoctorCheck(id: "launchd", title: title, state: .warn,
                               cause: "\(state), no pid\(exitNote)", fix: nil)
        case .unreadable:
            return DoctorCheck(id: "launchd", title: title, state: .warn,
                               cause: "launchctl print gave no job state", fix: nil)
        }
    }

    /// Whether the helper's last log line is its wait for the grant.
    static func logWaitsForGrant(_ line: String?) -> Bool {
        guard let line else { return false }
        return line.contains("waiting") && line.contains("permission grant")
    }

    static func fullDiskAccess(_ f: TelemetryFacts) -> DoctorCheck {
        let title = "Full Disk Access"
        guard case .loaded(_, .some, _) = f.launchd else {
            return DoctorCheck(id: "full-disk-access", title: title, state: .warn,
                               cause: "waits on a running launchd job", fix: nil)
        }
        if logWaitsForGrant(f.helperLogLastLine) {
            return DoctorCheck(id: "full-disk-access", title: title, state: .fail,
                               cause: "the service's log says it waits for the permission grant", fix: .openFullDiskAccess)
        }
        guard let mtime = f.spoolMtime else {
            return DoctorCheck(id: "full-disk-access", title: title, state: .fail,
                               cause: "the service runs but has written no spool", fix: .openFullDiskAccess)
        }
        let age = f.now.timeIntervalSince(mtime)
        if age > grantStaleAfter {
            return DoctorCheck(id: "full-disk-access", title: title, state: .fail,
                               cause: "the service runs but the spool was last written \(Int(age)) s ago", fix: .openFullDiskAccess)
        }
        return DoctorCheck(id: "full-disk-access", title: title, state: .pass,
                           cause: "the spool was written \(max(0, Int(age))) s ago", fix: nil)
    }

    static func spoolHealth(_ f: TelemetryFacts) -> DoctorCheck {
        let title = "Spool health"
        guard let es = f.esService else {
            return DoctorCheck(id: "spool", title: title, state: .warn,
                               cause: "the daemon did not report the spool", fix: nil)
        }
        let share = es.unparsedShare ?? 0
        let percent = Int((share * 100).rounded())
        let mtime = es.spoolMtimeDate ?? f.spoolMtime
        let stale = mtime.map { f.now.timeIntervalSince($0) > corruptStaleAfter } ?? true
        if share > 0.5 && stale {
            return DoctorCheck(id: "spool", title: title, state: .warn,
                               cause: "\(percent)% of the spool does not parse and nothing was written for 10 min",
                               fix: .setAsideSpool)
        }
        let flooding = es.flooding == true ? ", reader skipping ahead" : ""
        return DoctorCheck(id: "spool", title: title, state: .pass,
                           cause: "\(percent)% unparsed\(flooding)", fix: nil)
    }

    static func legacyHelper(_ f: TelemetryFacts) -> DoctorCheck {
        f.legacyInstalled
            ? DoctorCheck(id: "legacy", title: "Old helper", state: .fail,
                          cause: "an earlier version's helper in /Library shares the launchd label", fix: .removeLegacy)
            : DoctorCheck(id: "legacy", title: "Old helper", state: .pass,
                          cause: "none installed", fix: nil)
    }

    /// The daemon's own checks that are not `pass`, with their detail.
    static func daemonChecks(_ f: TelemetryFacts) -> [DoctorCheck] {
        guard let checks = f.daemonChecks else {
            return [DoctorCheck(id: "daemon", title: "Daemon", state: .fail,
                                cause: "the daemon did not answer /doctor", fix: nil)]
        }
        return checks.filter { $0.state != "pass" }.map { c in
            DoctorCheck(id: "daemon.\(c.id)", title: c.title, state: c.state == "fail" ? .fail : .warn,
                        cause: c.detail.flatMap { $0.isEmpty ? nil : $0 } ?? c.state, fix: nil)
        }
    }

    /// Renames the spool and its rotated sibling to `<name>.corrupt-<unix ts>`
    /// in the same directory; the collector recreates the spool. Returns the
    /// new paths.
    static func setAsideSpool(spoolPath: String, now: Date, fileManager: FileManager = .default) throws -> [String] {
        let stamp = Int(now.timeIntervalSince1970)
        var moved: [String] = []
        for path in [spoolPath, spoolPath + ".1"] where fileManager.fileExists(atPath: path) {
            let destination = "\(path).corrupt-\(stamp)"
            try fileManager.moveItem(atPath: path, toPath: destination)
            moved.append(destination)
        }
        return moved
    }

    /// Last non-empty line of a file's final 4 KB; nil when unreadable.
    static func lastLine(ofFileAt path: String) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        guard let size = try? handle.seekToEnd() else { return nil }
        let start = size > 4096 ? size - 4096 : 0
        guard (try? handle.seek(toOffset: start)) != nil,
              let data = try? handle.readToEnd() else { return nil }
        return String(decoding: data, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .last { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .map(String.init)
    }
}
