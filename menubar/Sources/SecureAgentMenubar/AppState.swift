import AppKit
import Foundation

/// Observable app state driving the menu-bar popover. Owns the daemon client and
/// the polling loop; the SwiftUI ConsoleView renders from its published values,
/// and the AppDelegate updates the status-bar icon via `onChange`.
@MainActor
public final class AppState: ObservableObject {
    @Published public private(set) var status: StatusResponse?
    @Published public private(set) var resources: ResourceSnapshotModel?
    @Published public private(set) var flags: [FlagModel] = []
    @Published public private(set) var incidents: [IncidentReportModel] = []
    @Published public private(set) var events: [EventModel] = []
    @Published public private(set) var connected = false
    @Published public var isPaused = false
    @Published public private(set) var guardRules: [GuardRuleModel] = []
    /// Per-rule notification overrides from the daemon (true = always page,
    /// false = never). Layered over notifyDefaultMinSeverity in shouldNotify.
    @Published public private(set) var notifyOverrides: [String: Bool] = [:]
    /// The daemon's default notification bar (ships as severity 3 — warnings
    /// queue silently in the popover/console, only criticals page).
    @Published public private(set) var notifyDefaultMinSeverity: Int = 3
    /// Flags the operator asked the advisor to re-read, keyed by flag id with
    /// the request time — the action sheet shows a spinner until the fresh
    /// verdict lands, and an honest failure note when it never does.
    @Published public private(set) var pendingRetriage: [String: Date] = [:]
    /// Transient advisor notice ("verdict updated" / "advisor didn't
    /// answer") — the popover surfaces it; nil when there is nothing to say.
    @Published public private(set) var advisorNotice: String?
    /// Verdict signatures captured when a re-triage is requested, so
    /// "verdict arrived" means CHANGED, not merely present.
    private var retriageBaseline: [String: String] = [:]
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

    #if DEBUG
    /// Test hook: seed flags directly (grouping tests).
    func seedFlagsForTesting(_ f: [FlagModel]) {
        self.flags = f
    }

    /// Test hook: age a pending re-triage past its timeout (expiry path).
    func agePendingRetriageForTesting(id: String) {
        pendingRetriage[id] = Date(timeIntervalSinceNow: -120)
    }
    #endif
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
            let notifyCfg = (try? await client.fetchNotifyRules()) ?? .fallback
            let resources = try? await client.fetchResources()
            // A pause requested mid-flight must not be overwritten by
            // results that were already in transit.
            guard !self.isPaused else { return }
            let wasDisconnected = !self.connected
            self.status = status
            self.resources = resources
            self.flags = flags
            self.incidents = incidents
            self.guardRules = guardRules
            self.notifyOverrides = notifyCfg.overrides
            self.notifyDefaultMinSeverity = notifyCfg.defaultMinSeverity
            self.reconcilePendingRetriage(flags: flags)
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
            self.resources = nil
            self.flags = []
            self.incidents = []
            self.events = []
            self.guardRules = []
            self.lastError = error.localizedDescription
            if wasConnected { self.scheduleTimer(5.0) }
            self.onChange?()
        }
    }

    /// The notification decision for one flag: the operator's per-rule
    /// override wins (explicit "always page" / "never page"); otherwise the
    /// daemon's default severity bar decides. Severity-1 informational flags
    /// (routine keychain-db opens) are silent unless the operator opts in.
    public func shouldNotify(for flag: FlagModel) -> Bool {
        if let override = notifyOverrides[flag.rule] { return override }
        return flag.severity >= notifyDefaultMinSeverity
    }

    /// Set or clear one rule's notification override (nil = back to default).
    /// Applied locally on success so the change feels instant; the next poll
    /// re-reads the daemon's store regardless.
    public func setNotifyOverride(rule: String, notify: Bool?) async {
        do {
            try await uiClient.setNotifyRule(rule: rule, notify: notify)
            if let notify {
                notifyOverrides[rule] = notify
            } else {
                notifyOverrides.removeValue(forKey: rule)
            }
            onChange?()
        } catch {
            reportLocalError("notification rule update failed: \(error.localizedDescription)")
        }
    }

    /// The advisor's live health straight from /status — nil on older
    /// daemons (treated as "unknown", not "offline").
    public var advisorHealth: AdvisorHealthModel? { status?.advisorHealth }

    /// Re-triage with honest feedback: mark the flag pending immediately so
    /// the sheet shows work-in-progress; the poll loop clears the marker when
    /// the fresh verdict arrives, or expires it with an explanation when the
    /// advisor never answers (model server down — the dead-button complaint).
    public func retriageFlagWithFeedback(_ flag: FlagModel) async {
        do {
            try await uiClient.retriageFlag(id: flag.id)
            retriageBaseline[flag.id] = Self.advisorSignature(flag.advisor)
            pendingRetriage[flag.id] = Date()
            onChange?()
        } catch {
            reportLocalError("advisor re-run failed: \(error.localizedDescription)")
        }
    }

    /// Clear the transient advisor notice (manual dismiss, or the auto-clear
    /// timer — the `matching` guard keeps a newer notice from being eaten by
    /// an older notice's timer).
    public func clearAdvisorNotice(matching: String? = nil) {
        if let matching, advisorNotice != matching { return }
        advisorNotice = nil
        onChange?()
    }

    /// Dismiss ONE flag (acknowledge): it stops counting as needing action
    /// without suppressing the class. Applied locally so the row leaves the
    /// list immediately; the daemon's store is the source of truth on the
    /// next poll.
    public func dismissFlag(_ flag: FlagModel) async {
        do {
            try await uiClient.acknowledgeFlag(id: flag.id)
            flags = flags.map { $0.id == flag.id ? $0.acknowledgedCopy() : $0 }
            onChange?()
        } catch {
            reportLocalError("dismiss failed: \(error.localizedDescription)")
        }
    }

    /// How long a re-triage stays "pending" before we call it unanswered.
    private static let retriageTimeout: TimeInterval = 90

    private static func advisorSignature(_ v: AdvisorVerdictModel?) -> String {
        guard let v else { return "" }
        return "\(v.assessment ?? "")|\(v.suggestedAction ?? "")|\(v.rationale)"
    }

    private func reconcilePendingRetriage(flags: [FlagModel]) {
        guard !pendingRetriage.isEmpty else { return }
        var changed = false
        for (id, requestedAt) in pendingRetriage {
            let current = flags.first(where: { $0.id == id })
            let landed = current != nil && Self.advisorSignature(current?.advisor) != (retriageBaseline[id] ?? "")
            if landed {
                pendingRetriage.removeValue(forKey: id)
                retriageBaseline.removeValue(forKey: id)
                advisorNotice = "Advisor verdict updated for \(current?.rule ?? "the flag")"
                changed = true
            } else if Date().timeIntervalSince(requestedAt) > Self.retriageTimeout {
                pendingRetriage.removeValue(forKey: id)
                retriageBaseline.removeValue(forKey: id)
                let offline = advisorHealth?.circuitOpen == true
                advisorNotice = offline
                    ? "Advisor is offline (circuit open) — check the local model server in Settings → Advisor"
                    : "Advisor didn't answer within 90s — the model server may be busy or down"
                changed = true
            }
        }
        if changed { onChange?() }
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
        for flag in flags where shouldNotify(for: flag) {
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
        public var totalCPUPercent: Double? {
            let parts = ([root] + children).compactMap(\.cpuPercent)
            return parts.isEmpty ? nil : parts.reduce(0, +)
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
        case impact

        var label: String {
            switch self {
            case .lastActivity: return "Last activity"
            case .created: return "Created"
            case .memory: return "Memory"
            case .impact: return "Impact"
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
        public var totalCPUPercent: Double? {
            let parts = trees.flatMap { [$0.0] + $0.1 }.compactMap(\.cpuPercent)
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
            case .impact:
                sorted = t.sorted {
                    familyImpact(rss: familyRSS($0.0, $0.1), cpu: familyCPU($0.0, $0.1)) >
                        familyImpact(rss: familyRSS($1.0, $1.1), cpu: familyCPU($1.0, $1.1))
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
        /// Family CPU (roots only; nil when daemon supplied no CPU data).
        public let familyCPUPercent: Double?
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
        case .impact:
            ordered = trees.sorted {
                familyImpact(rss: familyRSS($0.0, $0.1), cpu: familyCPU($0.0, $0.1)) >
                    familyImpact(rss: familyRSS($1.0, $1.1), cpu: familyCPU($1.0, $1.1))
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
            let famCPU = familyCPU(root, children)
            var rows = [AgentRow(agent: root, depth: 0,
                                 childCount: children.count,
                                 familyRSSBytes: famRSS,
                                 familyCPUPercent: famCPU,
                                 familyLastSeenAt: famSeen)]
            rows += children.map {
                AgentRow(agent: $0, depth: 1, childCount: 0,
                         familyRSSBytes: nil, familyCPUPercent: nil, familyLastSeenAt: nil)
            }
            return rows
        }
    }

    /// Session board: one row per tree root, helpers omitted. No cap — the
    /// popover scrolls. cwdLeaf on the agent is the glance label.
    public func sessionBoardRows(sortedBy sort: AgentSort) -> [AgentRow] {
        if let trees = status?.trees, !trees.isEmpty {
            let rows = trees.map { t in
                AgentRow(agent: t.root, depth: 0,
                         childCount: t.children.count,
                         familyRSSBytes: t.rssBytes,
                         familyCPUPercent: t.cpuPercent ?? familyCPU(t.root, t.children),
                         familyLastSeenAt: t.lastSeenAt)
            }
            return sortSessionRows(rows, by: sort)
        }
        return agentRows(sortedBy: sort).filter { $0.depth == 0 }
    }

    private func sortSessionRows(_ rows: [AgentRow], by sort: AgentSort) -> [AgentRow] {
        switch sort {
        case .created:
            return rows.sorted { ($0.agent.startedAt ?? "") < ($1.agent.startedAt ?? "") }
        case .memory:
            return rows.sorted { ($0.familyRSSBytes ?? 0) > ($1.familyRSSBytes ?? 0) }
        case .impact:
            return rows.sorted {
                familyImpact(rss: $0.familyRSSBytes, cpu: $0.familyCPUPercent) >
                    familyImpact(rss: $1.familyRSSBytes, cpu: $1.familyCPUPercent)
            }
        case .lastActivity:
            return rows.sorted { ($0.familyLastSeenAt ?? "") > ($1.familyLastSeenAt ?? "") }
        }
    }

    private func familyRSS(_ root: AgentSummaryModel, _ kids: [AgentSummaryModel]) -> UInt64? {
        let parts = ([root] + kids).compactMap(\.rssBytes)
        return parts.isEmpty ? nil : parts.reduce(0, +)
    }

    private func familyLastSeen(_ root: AgentSummaryModel, _ kids: [AgentSummaryModel]) -> String {
        ([root] + kids).compactMap(\.lastSeenAt).max() ?? ""
    }

    private func familyCPU(_ root: AgentSummaryModel, _ kids: [AgentSummaryModel]) -> Double? {
        let parts = ([root] + kids).compactMap(\.cpuPercent)
        return parts.isEmpty ? nil : parts.reduce(0, +)
    }

    /// Pressure relative to the first diagnostic thresholds: 4 GiB memory
    /// or one fully occupied core. The stronger signal wins.
    private func familyImpact(rss: UInt64?, cpu: Double?) -> Double {
        max(Double(rss ?? 0) / Double(4 * 1024 * 1024 * 1024), (cpu ?? 0) / 100)
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
        case .impact:
            return trees.sorted {
                familyImpact(rss: $0.totalRSSBytes, cpu: $0.totalCPUPercent) >
                    familyImpact(rss: $1.totalRSSBytes, cpu: $1.totalCPUPercent)
            }
        case .lastActivity:
            return trees.sorted { ($0.lastSeenAt ?? "") > ($1.lastSeenAt ?? "") }
        }
    }

    /// The human-meaningful count: distinct agent trees, not processes.
    public var activeAgentCount: Int { status?.activeAgents ?? agentRoots.count }

    /// Total tagged processes across all trees (helpers included).
    public var trackedProcessCount: Int { status?.trackedProcesses ?? activeAgents.count }

    public var uninspectedEgress: Int { status?.uninspectedEgress ?? 0 }

    /// Flags that still need a decision: not acknowledged, not covered by
    /// an incident row (the popover shows those as incident rows instead —
    /// one problem, one row), and not INFORMATIONAL (severity 1 — routine
    /// keychain-db opens queue silently in the console, they never demand
    /// a decision here).
    public var unactedFlags: [FlagModel] {
        flags.filter { $0.acknowledged != true && $0.severity >= 2 }
    }

    /// Tagged PIDs in one session tree (root plus helpers).
    public func treePIDs(rootPid: Int32) -> Set<Int32> {
        var pids: Set<Int32> = [rootPid]
        for a in activeAgents {
            if (a.rootPid ?? a.pid) == rootPid {
                pids.insert(a.pid)
            }
        }
        return pids
    }

    /// Unacted flags scoped to one session tree. nil root = every session.
    public func unactedFlagsForSession(rootPid: Int32?) -> [FlagModel] {
        let all = unactedFlags
        guard let rootPid else { return all }
        let pids = treePIDs(rootPid: rootPid)
        return all.filter { pids.contains($0.pid) }
    }

    /// A group of identical flags: same rule + agent + primary file/host.
    /// Repeated fires of the same pattern (codex touching the same keychain
    /// file every few minutes) are ONE decision, not twenty.
    public struct FlagGroup: Identifiable {
        public let rule: String
        public let agent: String
        /// The shared evidence anchor (file path or host) — "identical" is
        /// defined by this triple.
        public let anchor: String
        public let flags: [FlagModel]
        public var count: Int { flags.count }
        /// Newest fire in the group (the group's timestamp).
        public var newest: FlagModel { flags[0] }
        public var id: String { "\(rule)|\(agent)|\(anchor)" }
    }

    /// Group unacted flags by (rule, agent, anchor). Newest-first inside and
    /// across groups. The anchor is the first evidence line's file/host —
    /// matches what a human scans for ("same file again?").
    public func groupedUnactedFlags(forRootPid rootPid: Int32? = nil) -> [FlagGroup] {
        let unacted = unactedFlagsForSession(rootPid: rootPid)
        var groups: [String: [FlagModel]] = [:]
        var order: [String] = []
        for f in unacted {
            let key = f.rule + "|" + f.agent + "|" + (Self.flagGroupAnchor(f) ?? f.id)
            if groups[key] == nil { order.append(key) }
            groups[key, default: []].append(f)
        }
        return order.compactMap { key -> FlagGroup? in
            guard let list = groups[key], let first = list.first else { return nil }
            // Newest first inside the group.
            let sorted = list.sorted { $0.ts > $1.ts }
            return FlagGroup(rule: first.rule, agent: first.agent,
                             anchor: Self.flagGroupAnchor(first) ?? "", flags: sorted)
        }
    }

    /// The stable anchor for a flag: its primary file path or host — what
    /// makes two flags "the same problem" to a human.
    nonisolated static func flagGroupAnchor(_ f: FlagModel) -> String? {
        for line in f.evidence {
            if let r = line.range(of: "accessed keychain file ") {
                let rest = line[r.upperBound...]
                if let at = rest.range(of: " at ") { return String(rest[..<at.lowerBound]) }
                return String(rest)
            }
            if let r = line.range(of: "read ") {
                let rest = line[r.upperBound...]
                if let at = rest.range(of: " at ") { return String(rest[..<at.lowerBound]) }
            }
            if let r = line.range(of: "connected to ") {
                let rest = line[r.upperBound...]
                if let at = rest.range(of: " at ") { return String(rest[..<at.lowerBound]) }
            }
        }
        return nil
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

    public var monitorVendorKeyIDs: [String] {
        firewallRules.filter { $0.stat.type == "vendor-key" && ($0.stat.mode ?? "monitor") != "block" }.map(\.id).sorted()
    }

    public var showFleetPanel: Bool { status?.fleetConfigured == true }

    public func promoteVendorKeys() {
        Task {
            do {
                try await client.promoteFirewallType("vendor-key", mode: "block")
            } catch {
                self.lastError = "could not block vendor-key rules: \(error.localizedDescription)"
                self.onChange?()
            }
            self.fetch()
        }
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
