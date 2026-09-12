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
    /// Called when a severity-3 flag arrives after the baseline — the
    /// AppDelegate flashes the status-item badge so a critical leak attempt
    /// is noticed even when the popover is closed.
    public var onNewCriticalFlag: (() -> Void)?

    private let client: DaemonClientProtocol
    /// Shared client for one-off UI fetches (incident reports) — a fresh
    /// DaemonClient per sheet-open rebuilt nothing but churned allocations
    /// and made the socket path a per-open computation.
    public lazy var uiClient: DaemonClientProtocol = client
    /// Notification sink — a closure so tests can count deliveries instead of
    /// touching UNUserNotificationCenter.
    var notify: (FlagModel) -> Void = { NotificationManager.shared.sendNotification(for: $0) }
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

    public init(client: DaemonClientProtocol = DaemonClient()) {
        self.client = client
    }

    #if DEBUG
    /// Test hook: seed daemon-derived state without a live poll loop (the
    /// tree-grouping tests exercise pure view-data paths).
    func seedForTesting(status: StatusResponse) {
        self.status = status
        self.connected = true
    }
    #endif

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
        if isPaused {
            // Paused silences alerting, NOT consent: a pending guard decision
            // is an agent blocked mid-tool-call. Service it even while paused.
            presentGuardPromptFromPoll()
            return
        }
        guard !isFetching else { return }
        isFetching = true
        Task { await performFetch() }
    }

    /// While paused the full poll is gated off, but a pending guard decision is
    /// an agent blocked mid-tool-call — consent must keep flowing even when
    /// alerts are silenced.
    private func presentGuardPromptFromPoll() {
        guard !isFetching else { return }
        Task { [weak self] in
            guard let self else { return }
            do {
                let pending = try await self.client.fetchGuardPending()
                self.presentGuardPromptIfNeeded(pending)
            } catch {
                // The resume fetch re-surfaces transport problems; while paused
                // only the consent path needs to stay alive.
            }
        }
    }

    /// A single timeout is ambiguous (slow join vs. dead daemon) and a flap
    /// to "Disconnected" on one slow poll makes the UI lie. Require two
    /// consecutive transport failures before declaring disconnection; each
    /// transport error still surfaces via lastError for honesty.
    private var transportFailureStreak = 0

    /// The fetch core, awaitable — tests drive this directly; the timer/SSE
    /// paths use fetch() (fire-and-forget, serialized via isFetching).
    func performFetch() async {
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
            self.transportFailureStreak = 0
            if wasDisconnected { self.scheduleTimer(1.0) }
            self.eventsRefreshTick += 1
            self.processNewFlags(flags)
            self.onChange?()
            Task { await self.maybeSendWeeklyDigest() }
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
            self.transportFailureStreak += 1
            // Two consecutive transport failures: the daemon is really gone.
            // One timeout on a slow status join is NOT disconnection — the
            // daemon may be perfectly healthy (smoke test: 400 live pids
            // made /status take 2–4s, past the old 3s timeout, with zero
            // wrong answers).
            guard self.transportFailureStreak >= 2 else {
                self.lastError = error.localizedDescription
                self.onChange?()
                return
            }
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

    private func processNewFlags(_ flags: [FlagModel]) {
        if !didSeedNotificationBaseline {
            // First fetch after launch is a baseline, not news: every flag in
            // it may be days old. Notify only for ids that appear afterwards.
            notifiedFlagIDs.formUnion(flags.map(\.id))
            didSeedNotificationBaseline = true
            return
        }
        var sawCritical = false
        for flag in flags where flag.severity >= 2 {
            if notifiedFlagIDs.insert(flag.id).inserted {
                notify(flag)
                if flag.severity >= 3 { sawCritical = true }
            }
        }
        if sawCritical { onNewCriticalFlag?() }
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

    // MARK: - Weekly digest

    /// The scheduled proof the app is working: Monday 09:00, a one-line
    /// rollup of the week. Computed from rollups + audit + status, sent via
    /// the same notify-channel pattern as flag alerts (testable closure).
    var sendDigest: (String) -> Void = { NotificationManager.shared.sendWeeklyDigest($0) }

    /// Monday 09:00 local (± the poll window), once per ISO week.
    static func shouldSendWeeklyDigest(now: Date, lastSentWeek: String?, calendar: Calendar = .current) -> Bool {
        let week = calendar.component(.weekOfYear, from: now)
        let year = calendar.component(.yearForWeekOfYear, from: now)
        let key = "\(year)-W\(week)"
        guard key != lastSentWeek else { return false }
        guard calendar.component(.weekday, from: now) == 2, // Monday
              calendar.component(.hour, from: now) == 9 else { return false }
        return true
    }

    static func currentWeekKey(now: Date, calendar: Calendar = .current) -> String {
        "\(calendar.component(.yearForWeekOfYear, from: now))-W\(calendar.component(.weekOfYear, from: now))"
    }

    /// The one-line digest. Counts only — nothing posture-sensitive.
    static func weeklyDigestText(flags7d: Int, blockedLeaks: Int, approvals: Int, openIncidents: Int) -> String {
        let flag = flags7d == 1 ? "flag" : "flags"
        let leak = blockedLeaks == 1 ? "blocked leak" : "blocked leaks"
        let approval = approvals == 1 ? "allowlist approval" : "allowlist approvals"
        let incident = openIncidents == 1 ? "open incident" : "open incidents"
        return "\(flags7d) \(flag) · \(blockedLeaks) \(leak) · \(approvals) \(approval) · \(openIncidents) \(incident)"
    }

    private var digestCheckedThisWeek = false

    /// Called from performFetch after a successful status update: if it's
    /// Monday 09:00 and the digest hasn't gone out this ISO week, send it.
    func maybeSendWeeklyDigest(now: Date = Date()) async {
        let defaults = UserDefaults.standard
        let lastKey = defaults.string(forKey: "weeklyDigestLastWeek")
        guard Self.shouldSendWeeklyDigest(now: now, lastSentWeek: lastKey), !digestCheckedThisWeek else { return }
        digestCheckedThisWeek = true
        defaults.set(Self.currentWeekKey(now: now), forKey: "weeklyDigestLastWeek")

        let rollup = (try? await client.fetchRollup(hours: 168)) ?? []
        var flags7d = 0
        for p in rollup where p.kind.hasPrefix("flag:") { flags7d += p.count }
        let blocked = (status?.firewallStats ?? [:]).values.reduce(0) { $0 + $1.blocked }
        let weekAgo = now.addingTimeInterval(-7 * 86400)
        let approvals = ((try? await client.fetchAudit(limit: 50)) ?? []).filter {
            $0.action == "allowlist-add" && (ISO8601DateFormatter().date(from: $0.ts) ?? .distantPast) > weekAgo
        }.count
        let openIncidents = incidents.filter { $0.workflow?.status != "resolved" }.count
        sendDigest(Self.weeklyDigestText(flags7d: flags7d, blockedLeaks: blocked, approvals: approvals, openIncidents: openIncidents))
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
        let wasPaused = isPaused
        isPaused.toggle()
        if wasPaused {
            // Flags that queued while paused are baseline, not news: without
            // re-seeding, resume storms the user with every banner that
            // accrued during the break.
            didSeedNotificationBaseline = false
            notifiedFlagIDs.formUnion(flags.map(\.id))
            fetch()
        }
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
            do {
                try await client.setFirewallMode(rule: rule, mode: "block")
            } catch {
                // A refused promote must be visible: the user believes the
                // rule now blocks, and it silently still only monitors.
                self.lastError = "could not block \(rule): \(error.localizedDescription)"
                self.onChange?()
            }
            self.fetch()
        }
    }

    /// Settings screen: full mode control (monitor ↔ block), not just promote.
    public func setFirewallMode(rule: String, mode: String) {
        Task {
            do {
                try await client.setFirewallMode(rule: rule, mode: mode)
            } catch {
                self.lastError = "could not set \(rule) to \(mode): \(error.localizedDescription)"
            }
            self.fetch()
        }
    }

    public func revokeGuardRule(agent: String, ruleID: String) {
        Task {
            do {
                try await client.deleteGuardRule(agent: agent, ruleID: ruleID)
            } catch {
                // Revoking re-enables prompting for that path — a silently
                // dropped revoke means the user thinks they'll be re-asked
                // and they won't be.
                self.lastError = "could not revoke \(ruleID): \(error.localizedDescription)"
                self.onChange?()
            }
            self.fetch()
        }
    }

    /// Shows one native prompt for the oldest pending guard decision, deduping
    /// by id so the 1Hz poll doesn't stack a dialog on top of an open one.
    private func presentGuardPromptIfNeeded(_ pending: [GuardPending]) {
        guard promptingID == nil, let p = pending.first else { return }
        promptingID = p.id
        #if DEBUG
        // Test hook: NSAlert.runModal() cannot run in a test host; tests
        // assert on the dedupe id to prove the prompt path went live.
        if testHookSkipPromptDialog { return }
        #endif
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

    /// True when the app is showing a guard NSAlert — one at a time.
    public var promptingIDForTesting: String? { promptingID }

    /// Test hook: skip the modal NSAlert (untestable) while still proving the
    /// prompt path claimed the pending id.
    var testHookSkipPromptDialog = false

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

    /// Why "Open console" is unavailable right now, for tooltip/disabled
    /// states — nil when it can open. A silent no-op button reads as broken.
    public var dashboardUnavailableReason: String? {
        if !connected { return "The daemon is not running" }
        guard let status else { return "The daemon is not running" }
        guard status.proxyEnabled == true else { return "The inspection proxy is off (Settings → Agent routing)" }
        guard let port = status.proxyPort, port > 0 else { return "The console port is not open" }
        return nil
    }

    public func openDashboard() {
        // The console is served on the proxy's loopback HTTP port (and on the
        // unix API). Only open it when the daemon is connected and the proxy
        // is actually running — a stale port from a dead daemon opens a
        // browser error page.
        guard dashboardUnavailableReason == nil, let port = status?.proxyPort, port > 0 else { return }
        // The console's telemetry endpoints require the console token (a
        // credential agents never hold). Pass it as a query param; the page
        // lifts it into memory and sends it as a header on every fetch.
        var query = ""
        if let token = try? String(contentsOfFile: NSHomeDirectory() + "/.config/secure-agent/console-token",
                                   encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
           !token.isEmpty {
            // Hand off via fragment: fragments are never sent to the server,
            // so the token stays out of the wire, access logs, and Referer.
            // The console page lifts it into memory and strips it from the
            // address bar.
            query = "#ct=\(DaemonClient.urlQueryEscape(token))"
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

    // MARK: - Process tree

    /// Incremented on every successful fetch; the process detail sheet keys
    /// its live-tail task on this so each poll appends fresh transcript rows.
    @Published public private(set) var eventsRefreshTick = 0

    public var activeAgents: [AgentSummaryModel] { status?.agents ?? [] }

    /// Tree roots only: the popover lists agents, not their helper processes.

    /// Tree roots only: the popover lists agents, not their helper processes.
    /// Killing a root kills the tree (the daemon's /kill targets the tree).
    public var agentRoots: [AgentSummaryModel] {
        activeAgents.filter { ($0.rootPid ?? $0.pid) == $0.pid }
    }

    /// Tagged processes that are NOT tree roots — the subagents/helpers a
    /// session spawned. Grouping them under their parent turns "26 claude
    /// rows" into "3 sessions (with children)", which is what a human means
    /// by "how many agents do I have".
    public var childAgents: [AgentSummaryModel] {
        activeAgents.filter { let r = $0.rootPid ?? $0.pid; return r != $0.pid }
    }

    /// One row per tree: the root plus its direct children, sorted by the
    /// user's chosen key. Roots carry the family's aggregate memory so the
    /// list answers "what is this session costing" without expanding it.
    public struct AgentTree: Identifiable {
        public let root: AgentSummaryModel
        public let children: [AgentSummaryModel]
        /// Root RSS + all children (nil when the daemon supplied no RSS).
        public var totalRSSBytes: UInt64? {
            let parts = ([root] + children).compactMap(\.rssBytes)
            guard !parts.isEmpty else { return nil }
            return parts.reduce(0, +)
        }
        public var id: String { root.id }
        /// Most recent activity across the family — the tree-level liveness
        /// signal ("this session is working right now").
        public var lastSeenAt: String? {
            ([root] + children).compactMap(\.lastSeenAt).max()
        }
    }

    public enum AgentSort: String, CaseIterable, Sendable {
        case lastActivity
        case created
        case memory

        var label: String {
            switch self {
            case .lastActivity: return "Last activity"
            case .created: return "Created"
            case .memory: return "Memory"
            }
        }
    }

    /// Family membership by root_pid (the daemon's own family grouping —
    /// survives a middle process dying), falling back to ppid on older
    /// daemons that don't send root_pid.
    private func childrenOf(_ root: AgentSummaryModel, from kids: [AgentSummaryModel]) -> [AgentSummaryModel] {
        kids.filter { $0.rootPid == root.pid || ($0.rootPid == nil && $0.ppid == root.pid) }
            .sorted { ($0.startedAt ?? "") < ($1.startedAt ?? "") }
    }

    /// Collectors the supervisor gave up on — surfaced in the popover, since
    /// "eslogger failed permanently" is the reason transcripts would be thin
    /// and silence must not read as healthy.
    public var abandonedCollectors: [HealthModel]? {
        guard let cs = status?.collectors else { return nil }
        let dead = cs.filter { $0.abandoned }
        return dead.isEmpty ? nil : dead
    }

    /// One harness (provider) with its sessions grouped beneath it — the
    /// two-level organization: "my 40 claude/codex/cursor processes" reads
    /// as 3 harness groups, each expandable to its sessions, each session
    /// expandable to its subagents. Collapsed state is UI-only; the model
    /// just supplies the structure.
    public struct HarnessGroup: Identifiable {
        /// Harness name ("claude", "cursor", "codex") — the group header.
        public let name: String
        /// Sessions (tree roots) in this harness, with their children.
        public var trees: [(AgentSummaryModel, [AgentSummaryModel])]
        /// Family memory across the whole harness.
        public var totalRSSBytes: UInt64? {
            let parts = trees.flatMap { [$0.0] + $0.1 }.compactMap(\.rssBytes)
            return parts.isEmpty ? nil : parts.reduce(0, +)
        }
        public var sessionCount: Int { trees.count }
        public var processCount: Int { trees.reduce(0) { $0 + 1 + $1.1.count } }
        public var lastSeenAt: String? {
            trees.flatMap { [$0.0] + $0.1 }.compactMap(\.lastSeenAt).max()
        }
        public var id: String { name }
    }

    /// Harness groups, sessions inside sorted by the user's key.
    public func harnessGroups(sortedBy sort: AgentSort) -> [HarnessGroup] {
        let kids = childAgents
        var byHarness: [String: [(AgentSummaryModel, [AgentSummaryModel])]] = [:]
        for root in agentRoots {
            let children = childrenOf(root, from: kids)
            byHarness[root.name, default: []].append((root, children))
        }
        var groups: [HarnessGroup] = byHarness.map { name, trees in
            HarnessGroup(name: name, trees: trees)
        }
        for i in groups.indices {
            let t = groups[i].trees
            let sorted: [(AgentSummaryModel, [AgentSummaryModel])]
            switch sort {
            case .created:
                sorted = t.sorted { $0.0.startedAt ?? "" < $1.0.startedAt ?? "" }
            case .memory:
                sorted = t.sorted {
                    (familyRSS($0.0, $0.1) ?? 0) > (familyRSS($1.0, $1.1) ?? 0)
                }
            case .lastActivity:
                sorted = t.sorted { familyLastSeen($0.0, $0.1) > familyLastSeen($1.0, $1.1) }
            }
            groups[i].trees = sorted
        }
        // Groups by their own strongest activity.
        return groups.sorted { ($0.lastSeenAt ?? "") > ($1.lastSeenAt ?? "") }
    }

    /// Flat, pre-sorted rows for the popover list — roots carry a depth and
    /// the family aggregate so the View layer is one dumb ForEach with zero
    /// nested-generic inference (nested AgentTree + .children keypaths made
    /// SwiftUI's ForEach overloads ambiguous).
    public struct AgentRow: Identifiable {
        public let agent: AgentSummaryModel
        /// 0 = session root, 1 = direct child of a root.
        public let depth: Int
        /// Number of subprocesses under this row (roots only).
        public let childCount: Int
        /// Family memory (roots only; nil when daemon supplied no RSS).
        public let familyRSSBytes: UInt64?
        /// Most recent activity in the family (roots only).
        public let familyLastSeenAt: String?
        public var id: String { agent.id }
    }

    /// One row per process, trees grouped, sorted by the chosen key.
    /// Children are ordered oldest-first within a tree (spawn order reads
    /// like a story); trees by the user's key.
    public func agentRows(sortedBy sort: AgentSort) -> [AgentRow] {
        let kids = childAgents
        let trees = agentRoots.map { root -> (AgentSummaryModel, [AgentSummaryModel]) in
            (root, childrenOf(root, from: kids))
        }
        let ordered: [(AgentSummaryModel, [AgentSummaryModel])]
        switch sort {
        case .created:
            // Newest session last (reading top-down = chronological).
            ordered = trees.sorted { $0.0.startedAt ?? "" < $1.0.startedAt ?? "" }
        case .memory:
            ordered = trees.sorted {
                (familyRSS($0.0, $0.1) ?? 0) > (familyRSS($1.0, $1.1) ?? 0)
            }
        case .lastActivity:
            // Most recently active first: the session the user probably
            // wants to look at is at the top.
            ordered = trees.sorted {
                familyLastSeen($0.0, $0.1) > familyLastSeen($1.0, $1.1)
            }
        }
        return ordered.flatMap { root, children in
            let famRSS = familyRSS(root, children)
            let famSeen = familyLastSeen(root, children)
            var rows = [AgentRow(agent: root, depth: 0,
                                 childCount: children.count,
                                 familyRSSBytes: famRSS,
                                 familyLastSeenAt: famSeen)]
            rows += children.map {
                AgentRow(agent: $0, depth: 1, childCount: 0,
                         familyRSSBytes: nil, familyLastSeenAt: nil)
            }
            return rows
        }
    }

    private func familyRSS(_ root: AgentSummaryModel, _ kids: [AgentSummaryModel]) -> UInt64? {
        let parts = ([root] + kids).compactMap(\.rssBytes)
        return parts.isEmpty ? nil : parts.reduce(0, +)
    }

    private func familyLastSeen(_ root: AgentSummaryModel, _ kids: [AgentSummaryModel]) -> String {
        ([root] + kids).compactMap(\.lastSeenAt).max() ?? ""
    }

    /// Trees sorted by the chosen key (structured form; the popover uses
    /// the flat `agentRows`).
    public func agentTrees(sortedBy sort: AgentSort) -> [AgentTree] {
        let kids = childAgents
        let trees = agentRoots.map { root -> AgentTree in
            AgentTree(root: root, children: childrenOf(root, from: kids))
        }
        switch sort {
        case .created:
            return trees.sorted { ($0.root.startedAt ?? "") < ($1.root.startedAt ?? "") }
        case .memory:
            return trees.sorted { ($0.totalRSSBytes ?? 0) > ($1.totalRSSBytes ?? 0) }
        case .lastActivity:
            return trees.sorted { ($0.lastSeenAt ?? "") > ($1.lastSeenAt ?? "") }
        }
    }

    /// The human-meaningful count: distinct agent trees, not processes.
    public var activeAgentCount: Int { status?.activeAgents ?? agentRoots.count }

    /// Total tagged processes across all trees (helpers included).
    public var trackedProcessCount: Int { status?.trackedProcesses ?? activeAgents.count }

    public var uninspectedEgress: Int { status?.uninspectedEgress ?? 0 }

    /// Flags that still need a decision: not acknowledged and not covered by
    /// an incident row (the popover shows those as incident rows instead —
    /// one problem, one row).
    public var unactedFlags: [FlagModel] {
        flags.filter { $0.acknowledged != true }
    }

    /// Total resident memory across every tagged agent process — the header's
    /// glanceable "what do my agents cost" number. nil when the daemon
    /// supplied no RSS (older daemons).
    public var totalAgentMemory: UInt64? {
        let parts = activeAgents.compactMap(\.rssBytes)
        guard !parts.isEmpty else { return nil }
        return parts.reduce(0, +)
    }

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

    /// All-clear hero state for previews/snapshots.
    public static func previewProtected() -> AppState {
        let s = AppState()
        s.status = StatusResponse(
            running: true, uptime: "2h 5m", activeAgents: 1,
            agents: [AgentSummaryModel(pid: 901, name: "claude", cwd: "/Users/dev/app")],
            proxyEnabled: true, proxyPort: 8443, uninspectedEgress: 0,
            firewallStats: ["anthropic-key": RuleStatModel(wouldBlock: 0, blocked: 0, legit: 41, mode: "monitor")])
        s.connected = true
        return s
    }

    /// Attention hero state (would-block + uninspected + a warning flag).
    public static func previewAttention() -> AppState {
        let s = AppState()
        s.status = StatusResponse(
            running: true, uptime: "2h 5m", activeAgents: 1,
            agents: [AgentSummaryModel(pid: 901, name: "cursor", cwd: "/Users/dev/web-app")],
            proxyEnabled: true, proxyPort: 8443, uninspectedEgress: 2,
            firewallStats: [
                "anthropic-key": RuleStatModel(wouldBlock: 3, blocked: 0, legit: 12, mode: "monitor"),
                "aws-key": RuleStatModel(wouldBlock: 0, blocked: 0, legit: 5, mode: "block"),
            ])
        s.flags = [FlagModel(id: "f9", rule: "keychain-access", severity: 2, ts: "",
                             pid: 901, agent: "cursor",
                             evidence: ["cursor (pid 901) accessed keychain file login.keychain-db at 2026-09-08T09:00:00Z"])]
        s.connected = true
        return s
    }
}
