import AppKit
import Foundation

/// Observable app state driving the menu-bar popover. Owns the daemon client and
/// the polling loop; the SwiftUI ConsoleView renders from its published values,
/// and the AppDelegate updates the status-bar icon via `onChange`.
@MainActor
public final class AppState: ObservableObject {
    @Published public private(set) var status: StatusResponse?
    @Published public private(set) var flags: [FlagModel] = []
    @Published public private(set) var incidents: [IncidentReportModel] = []
    @Published public private(set) var events: [EventModel] = []
    @Published public private(set) var connected = false
    @Published public var isPaused = false
    @Published public private(set) var guardRules: [GuardRuleModel] = []

    /// Called after every state change so the AppDelegate can refresh the icon.
    public var onChange: (() -> Void)?

    private let client = DaemonClient()
    private var notifiedFlagIDs: Set<String> = []
    private var timer: Timer?
    /// The pending-prompt id currently shown in an NSAlert, so the 1Hz poll
    /// doesn't stack a second dialog on top while one is already up.
    private var promptingID: String?

    public init() {}

    public func start() {
        fetch()
        scheduleTimer(1.0)
    }

    private func scheduleTimer(_ interval: TimeInterval) {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.fetch() }
        }
    }

    public func fetch() {
        guard !isPaused else { return }
        Task {
            do {
                let status = try await client.fetchStatus()
                let flags = try await client.fetchFlags(limit: 20)
                let incidents = (try? await client.fetchIncidents(limit: 10)) ?? []
                let events = try await client.fetchEvents(limit: 50)
                let guardRules = (try? await client.fetchGuardRules()) ?? []
                let wasDisconnected = !self.connected
                self.status = status
                self.flags = flags
                self.incidents = incidents
                self.events = events
                self.guardRules = guardRules
                self.connected = true
                if wasDisconnected { self.scheduleTimer(1.0) }
                self.processNewFlags(flags)
                self.onChange?()
                // Presented last: runModal() blocks this Task until the user
                // responds, so the icon/console refresh above isn't held up.
                let pending = (try? await client.fetchGuardPending()) ?? []
                self.presentGuardPromptIfNeeded(pending)
            } catch {
                let wasConnected = self.connected
                self.connected = false
                self.incidents = []
                if wasConnected { self.scheduleTimer(5.0) }
                self.onChange?()
            }
        }
    }

    private func processNewFlags(_ flags: [FlagModel]) {
        for flag in flags where flag.severity >= 2 {
            if notifiedFlagIDs.insert(flag.id).inserted {
                NotificationManager.shared.sendNotification(for: flag)
            }
        }
    }

    // MARK: - Actions

    public func refresh() { fetch() }

    public func togglePause() {
        isPaused.toggle()
        if !isPaused { fetch() }
        onChange?()
    }

    public func kill(pid: Int32) {
        Task {
            _ = try? await client.killProcess(pid: pid)
            self.fetch()
        }
    }

    public func promote(rule: String) {
        Task {
            try? await client.setFirewallMode(rule: rule, mode: "block")
            self.fetch()
        }
    }

    public func revokeGuardRule(agent: String, ruleID: String) {
        Task {
            try? await client.deleteGuardRule(agent: agent, ruleID: ruleID)
            self.fetch()
        }
    }

    /// Shows one native prompt for the oldest pending guard decision, deduping
    /// by id so the 1Hz poll doesn't stack a dialog on top of an open one.
    private func presentGuardPromptIfNeeded(_ pending: [GuardPending]) {
        guard promptingID == nil, let p = pending.first else { return }
        promptingID = p.id
        let alert = NSAlert()
        alert.messageText = "Allow \(p.agent) to access this?"
        alert.informativeText = "\(p.tool) → \(p.path)\nRule: \(p.ruleID)"
        alert.addButton(withTitle: "Allow Once")
        alert.addButton(withTitle: "Allow Always")
        alert.addButton(withTitle: "Deny")
        let r = alert.runModal()
        let decision: GuardResolveRequest
        switch r {
        case .alertFirstButtonReturn:  decision = .init(id: p.id, verdict: "allow", scope: "once")
        case .alertSecondButtonReturn: decision = .init(id: p.id, verdict: "allow", scope: "always")
        default:                       decision = .init(id: p.id, verdict: "deny", scope: "always")
        }
        Task { try? await client.resolveGuard(decision); self.promptingID = nil; self.fetch() }
    }

    public func openDashboard() {
        let port = status?.proxyPort ?? 8443
        if let url = URL(string: "http://localhost:\(port)/dashboard/") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: - Derived view data

    public var statusText: String {
        if !connected { return "Disconnected" }
        if let up = status?.uptime, !up.isEmpty { return "Active · uptime \(up)" }
        return "Active"
    }

    public var activeAgents: [AgentSummaryModel] { status?.agents ?? [] }

    public var uninspectedEgress: Int { status?.uninspectedEgress ?? 0 }

    public struct FirewallRuleRow: Identifiable {
        public let id: String
        public let stat: RuleStatModel
    }

    /// Firewall rules sorted by id, with their stats.
    public var firewallRules: [FirewallRuleRow] {
        (status?.firewallStats ?? [:]).sorted { $0.key < $1.key }.map { FirewallRuleRow(id: $0.key, stat: $0.value) }
    }

    public var firewallWouldBlock: Int { firewallRules.reduce(0) { $0 + $1.stat.wouldBlock } }
    public var firewallBlocked: Int { firewallRules.reduce(0) { $0 + $1.stat.blocked } }
    public var isEnforcing: Bool { firewallRules.contains { $0.stat.blocked > 0 } }

    /// Populated state for previews/snapshots (no daemon needed).
    public static func preview() -> AppState {
        let s = AppState()
        s.status = StatusResponse(
            running: true, uptime: "4h 12m", activeAgents: 2,
            agents: [
                AgentSummaryModel(pid: 5821, name: "claude", cwd: "/Users/dev/workspace/api-service"),
                AgentSummaryModel(pid: 6033, name: "cursor", cwd: "/Users/dev/projects/web-app"),
            ],
            proxyEnabled: true, proxyPort: 8443, uninspectedEgress: 2,
            firewallStats: [
                "anthropic-key": RuleStatModel(wouldBlock: 5, blocked: 0, legit: 12, mode: "monitor"),
                "aws-key": RuleStatModel(wouldBlock: 2, blocked: 1, legit: 0, mode: "block"),
            ])
        s.flags = [FlagModel(id: "f1", rule: "proxy-secret-leak", severity: 3, ts: "",
                             pid: 6033, agent: "cursor",
                             evidence: ["anthropic-key detected in request body to logs.example.com"])]
        s.connected = true
        return s
    }
}
