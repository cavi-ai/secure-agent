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
    /// Last transport/decode failure, surfaced in the UI. A daemon that answers
    /// with garbage is NOT "Disconnected" — it is up and misbehaving, which the
    /// user must be able to tell apart from a dead daemon.
    @Published public private(set) var lastError: String?

    /// Called after every state change so the AppDelegate can refresh the icon.
    public var onChange: (() -> Void)?

    private let client = DaemonClient()
    private var notifiedFlagIDs: Set<String> = []
    /// False until the first successful fetch seeds the notification baseline —
    /// without it, launch fires up to 20 banners for days-old flags.
    private var didSeedNotificationBaseline = false
    private var timer: Timer?
    /// Serializes fetch() so a slow daemon can't stack overlapping poll tasks
    /// that complete out of order and regress state.
    private var isFetching = false
    /// The pending-prompt id currently shown in an NSAlert, so the 1Hz poll
    /// doesn't stack a second dialog on top while one is already up.
    private var promptingID: String?
    /// SSE push channel. When live, events drive refreshes and the poll timer
    /// drops to a slow status cadence; when the endpoint is missing (old
    /// daemon) or keeps failing, we fall back to the 1Hz poll.
    private var streamTask: Task<Void, Never>?
    private var streamFailureCount = 0
    /// True when the daemon's /events/stream answered 503 (old daemon build):
    /// stay on polling permanently for this session.
    private var streamUnavailable = false
    /// Debounces SSE-driven refreshes (one event per syscall would otherwise
    /// refetch per event).
    private var refreshTask: Task<Void, Never>?

    public init() {}

    public func start() {
        fetch()
        scheduleTimer(1.0)
        startEventStream()
    }

    // MARK: - Event stream (SSE push)

    /// Opens /events/stream and lets events drive refreshes. Reconnect policy:
    /// capped exponential backoff with jitter; a 503 (endpoint not enabled —
    /// old daemon) switches permanently to polling for this session; repeated
    /// transport failures keep the poll timer at its fast cadence as fallback.
    private func startEventStream() {
        streamTask?.cancel()
        streamTask = Task { [weak self] in
            var backoff: UInt64 = 1_000_000_000 // 1s
            while !Task.isCancelled {
                guard let self, !self.streamUnavailable else { return }
                do {
                    try await self.client.streamEvents { frame in
                        Task { @MainActor [weak self] in
                            self?.handleStreamEvent(frame)
                        }
                    }
                    // Stream ended without error: treat as a failure and retry.
                    throw DaemonClientError.transport("stream ended")
                } catch is CancellationError {
                    return
                } catch let DaemonClientError.http(code) where code == 503 {
                    self.streamUnavailable = true
                    return // old daemon: polling carries the session
                } catch {
                    self.streamFailureCount += 1
                    // While the stream is down, the existing poll cadence
                    // (1s connected / 5s disconnected) covers freshness.
                    try? await Task.sleep(nanoseconds: backoff)
                    // ±20% jitter so reconnects don't phase-lock.
                    let jitter = UInt64.random(in: 0...(backoff / 5 + 1))
                    backoff = min(backoff * 2 + jitter, 30_000_000_000)
                }
            }
        }
    }

    private func handleStreamEvent(_ frame: SSEFrame) {
        streamFailureCount = 0
        // The stream being alive at all is proof of daemon liveness. On
        // reconnect, pull full state once (events seen while disconnected
        // are not replayed — the refetch closes the gap).
        if !connected {
            connected = true
            scheduleTimer(30.0) // stream carries freshness; slow poll for uptime
            fetch()
        }
        switch frame.event {
        case "guard-prompt", "guard-resolved":
            // Instant path: a waiting user decision must not wait for a poll.
            scheduleLightRefresh(immediately: true)
        default:
            // Any bus event can precede a new flag (correlator consumes the
            // same bus) — debounce to one refresh per burst.
            scheduleLightRefresh(immediately: false)
        }
    }

    /// Debounced partial refresh: flags + guard pending only (status/uptime
    /// stay on the slow poll — they change on a seconds scale, not per event).
    private func scheduleLightRefresh(immediately: Bool) {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            if !immediately {
                try? await Task.sleep(nanoseconds: 400_000_000)
            }
            guard !Task.isCancelled, let self, !self.isPaused else { return }
            do {
                let flags = try await self.client.fetchFlags(limit: 20)
                guard !Task.isCancelled else { return }
                self.flags = flags
                self.processNewFlags(flags)
                self.onChange?()
                let pending = try await self.client.fetchGuardPending()
                self.presentGuardPromptIfNeeded(pending)
            } catch {
                // The next stream event or poll tick retries; no state flip here.
            }
        }
    }

    private func scheduleTimer(_ interval: TimeInterval) {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.fetch() }
        }
    }

    public func fetch() {
        guard !isPaused, !isFetching else { return }
        isFetching = true
        Task {
            defer { self.isFetching = false }
            do {
                let status = try await client.fetchStatus()
                let flags = try await client.fetchFlags(limit: 20)
                let incidents = (try? await client.fetchIncidents(limit: 10)) ?? []
                let guardRules = (try? await client.fetchGuardRules()) ?? []
                // A pause requested mid-flight must not be overwritten by
                // results that were already in transit.
                guard !self.isPaused else { return }
                let wasDisconnected = !self.connected
                self.status = status
                self.flags = flags
                self.incidents = incidents
                self.guardRules = guardRules
                self.connected = true
                self.lastError = nil
                if wasDisconnected { self.scheduleTimer(1.0) }
                self.processNewFlags(flags)
                self.onChange?()
                // Guard pending is decoded STRICTLY: a malformed response that
                // silently became [] would suppress the Allow/Deny prompt — a
                // fail-open on the security-critical path.
                do {
                    let pending = try await client.fetchGuardPending()
                    guard !self.isPaused else { return }
                    // Presented last: runModal() blocks this Task until the user
                    // responds, so the icon/console refresh above isn't held up.
                    self.presentGuardPromptIfNeeded(pending)
                } catch {
                    self.lastError = "guard check failed: \(error.localizedDescription)"
                    self.onChange?()
                }
            } catch let DaemonClientError.decode(msg) {
                // Daemon answered but spoke garbage: still connected, but say so.
                self.lastError = "decode error: \(msg)"
                self.onChange?()
            } catch {
                let wasConnected = self.connected
                self.connected = false
                // Drop ALL daemon-derived state: stale flags/incidents driving
                // the icon and console while the header says "Disconnected" is
                // how a user kills the wrong process.
                self.status = nil
                self.flags = []
                self.incidents = []
                self.events = []
                self.guardRules = []
                self.lastError = error.localizedDescription
                if wasConnected { self.scheduleTimer(5.0) }
                self.onChange?()
            }
        }
    }

    private func processNewFlags(_ flags: [FlagModel]) {
        if !didSeedNotificationBaseline {
            // First fetch after launch is a baseline, not news: every flag in
            // it may be days old. Notify only for ids that appear afterwards.
            notifiedFlagIDs.formUnion(flags.map(\.id))
            didSeedNotificationBaseline = true
            return
        }
        for flag in flags where flag.severity >= 2 {
            if notifiedFlagIDs.insert(flag.id).inserted {
                NotificationManager.shared.sendNotification(for: flag)
            }
        }
        // Bound the dedupe set: it only ever inserts otherwise.
        if notifiedFlagIDs.count > 500 {
            let live = Set(flags.map(\.id))
            notifiedFlagIDs.formIntersection(live)
        }
    }

    /// Cancel the stream, debounce task, and poll timer (app quit path).
    public func stop() {
        streamTask?.cancel()
        refreshTask?.cancel()
        timer?.invalidate()
        timer = nil
    }

    // MARK: - Actions

    /// Surfaces a local (non-daemon) failure in the same banner as daemon
    /// errors — e.g. the guard-modes.json write failing.
    public func reportLocalError(_ message: String) {
        lastError = message
        onChange?()
    }

    public func refresh() { fetch() }

    public func togglePause() {
        isPaused.toggle()
        if !isPaused { fetch() }
        onChange?()
    }

    public func kill(pid: Int32) {
        Task {
            do {
                let ok = try await client.killProcess(pid: pid)
                if !ok {
                    self.lastError = "kill of pid \(pid) was refused by the daemon"
                }
            } catch {
                self.lastError = "kill failed: \(error.localizedDescription)"
            }
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
        alert.messageText = Self.guardPromptHeadline(p)
        var informative = Self.guardPromptDetail(p)
        // Disclose what "Allow Always" really approves, so consent is informed.
        if let scope = p.scopeText, !scope.isEmpty {
            informative += "\n\n⚠️ \(scope)"
        }
        alert.informativeText = informative
        let allowOnceButton = alert.addButton(withTitle: "Allow Once")
        let allowAlwaysButton = alert.addButton(withTitle: "Allow Always")
        let denyButton = alert.addButton(withTitle: "Deny")
        // Safe default: NSAlert binds Return to the first button unless told
        // otherwise, and NSApp.activate below can steal focus right as this
        // modal appears — an accidental Return must deny, never approve.
        allowOnceButton.keyEquivalent = ""
        allowAlwaysButton.keyEquivalent = ""
        denyButton.keyEquivalent = "\r"
        NSApp.activate(ignoringOtherApps: true)
        let r = alert.runModal()
        let decision: GuardResolveRequest
        switch r {
        case .alertFirstButtonReturn:  decision = .init(id: p.id, verdict: "allow", scope: "once")
        case .alertSecondButtonReturn: decision = .init(id: p.id, verdict: "allow", scope: "always")
        case .alertThirdButtonReturn:  decision = .init(id: p.id, verdict: "deny", scope: "always")
        default:                       decision = .init(id: p.id, verdict: "deny", scope: "once")
        }
        // A resolve failure must be visible: the user believes they decided,
        // and a silently dropped decision re-prompts a second later with no
        // explanation. Keep the error on screen; the pending item stays
        // server-side and will re-prompt.
        Task {
            do {
                try await client.resolveGuard(decision)
            } catch {
                self.lastError = "decision not recorded (daemon unreachable): \(error.localizedDescription)"
            }
            self.promptingID = nil
            self.fetch()
        }
    }

    // MARK: - Guard prompt language

    /// Plain-language headline: what is this file, and who wants it.
    static func guardPromptHeadline(_ p: GuardPending) -> String {
        switch p.ruleID {
        case "ssh-keys": return "\(p.agent.capitalized) wants to read an SSH private key"
        case "cloud-creds": return "\(p.agent.capitalized) wants to read a cloud credential file"
        case "keychain": return "\(p.agent.capitalized) wants to touch your keychain"
        case "env-files": return "\(p.agent.capitalized) wants to read an environment file (secrets inside)"
        case "shell-rc": return "\(p.agent.capitalized) wants to access a shell config file"
        default: return "Allow \(p.agent) to access this?"
        }
    }

    /// Detail line: the concrete file, why it matters, what is being asked.
    static func guardPromptDetail(_ p: GuardPending) -> String {
        let why: String
        switch p.ruleID {
        case "ssh-keys":
            why = "A leaked SSH key grants access to every server it authenticates."
        case "cloud-creds":
            why = "A leaked cloud key can create resources, read data, or run workloads on your account."
        case "keychain":
            why = "The keychain holds every password and certificate on this Mac."
        case "env-files":
            why = ".env files carry API keys and database passwords for this project."
        case "shell-rc":
            why = "Shell config controls every future terminal session — a silent edit affects everything."
        default:
            why = ""
        }
        var lines = "\(p.tool) → \(p.path)"
        if !why.isEmpty { lines += "\n\n\(why)" }
        lines += "\nRule: \(p.ruleID)"
        return lines
    }

    public func openDashboard() {
        // The console is served on the proxy's loopback HTTP port (and on the
        // unix API). Only open it when the daemon is connected and the proxy
        // is actually running — a stale port from a dead daemon opens a
        // browser error page.
        guard connected, status?.proxyEnabled == true, let port = status?.proxyPort, port > 0 else { return }
        // The console's telemetry endpoints require the console token (a
        // credential agents never hold). Pass it as a query param; the page
        // lifts it into memory and sends it as a header on every fetch.
        var query = ""
        if let token = try? String(contentsOfFile: NSHomeDirectory() + "/.config/secure-agent/console-token",
                                   encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
           !token.isEmpty {
            query = "?ct=\(DaemonClient.urlQueryEscape(token))"
        }
        if let url = URL(string: "http://127.0.0.1:\(port)/dashboard/\(query)") {
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
