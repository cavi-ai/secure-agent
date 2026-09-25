import XCTest
@testable import SecureAgentMenubar

/// Stub DaemonClient: programmable responses, no socket.
final class StubDaemonClient: DaemonClientProtocol, @unchecked Sendable {
    var status = StatusResponse(running: true, uptime: "1m", activeAgents: 1, agents: [],
                                proxyEnabled: false, proxyPort: 0, uninspectedEgress: 0,
                                firewallStats: nil)
    var flags: [FlagModel] = []
    var pending: [GuardPending] = []
    var statusError: Error?
    var guardError: Error?
    var resources = ResourceSnapshotModel(host: nil)

    func fetchStatus() async throws -> StatusResponse {
        if let statusError { throw statusError }
        return status
    }
    func fetchResources() async throws -> ResourceSnapshotModel { resources }
    var fetchFlagsCalls = 0
    func fetchFlags(limit: Int) async throws -> [FlagModel] {
        fetchFlagsCalls += 1
        return flags
    }
    func fetchIncidents(limit: Int) async throws -> [IncidentReportModel] { [] }
    var posture = PostureModel(state: "all-clear", needsYou: 0, summary: "", connected: true)
    func fetchPosture() async throws -> PostureModel { posture }
    func retriageFlag(id: String) async throws { }
    var acknowledgedFlagIDs: [String] = []
    var acknowledgeError: Error?
    func acknowledgeFlag(id: String) async throws {
        if let acknowledgeError { throw acknowledgeError }
        acknowledgedFlagIDs.append(id)
        // Mirrors the real daemon closing the loop: the next /flags read
        // shows the flag acknowledged.
        flags = flags.map { $0.id == id ? $0.acknowledgedCopy() : $0 }
    }
    func fetchGuardPathAllows() async throws -> [GuardPathAllowModel] { [] }
    func deleteGuardPathAllow(agent: String, ruleID: String, path: String) async throws { }
    func fetchMutes() async throws -> [(rule: String, host: String, agent: String?, title: String?)] { [] }
    func muteRemove(rule: String, host: String, agent: String?) async throws { }
    var notifyRules = NotifyRulesResponse.fallback
    var setNotifyRuleCalls: [(rule: String, notify: Bool?)] = []
    func fetchNotifyRules() async throws -> NotifyRulesResponse { notifyRules }
    func setNotifyRule(rule: String, notify: Bool?) async throws {
        setNotifyRuleCalls.append((rule, notify))
    }
    func fetchGuardRules() async throws -> [GuardRuleModel] { [] }
    func fetchGuardPending() async throws -> [GuardPending] {
        if let guardError { throw guardError }
        return pending
    }
    func resolveGuard(_ req: GuardResolveRequest) async throws {}
    func killProcess(pid: Int32) async throws -> Bool { true }
    func deleteGuardRule(agent: String, ruleID: String) async throws {}
    func setFirewallMode(rule: String, mode: String) async throws {}
    func promoteFirewallType(_ secretType: String, mode: String) async throws {}
    func fetchAdvisorDiscover() async throws -> AdvisorDiscovery {
        AdvisorDiscovery(servers: [], managedModels: [])
    }
    func fetchRollup(hours: Int) async throws -> [RollupPointModel] { [] }
    func fetchAudit(limit: Int) async throws -> [AuditEntryModel] { [] }
    func streamEvents(onEvent: @escaping @Sendable (SSEFrame) -> Void) async throws {
        try await Task.sleep(nanoseconds: 60_000_000_000) // tests don't drive SSE
    }
    var performed: [FlagExplainAction] = []
    var performError: Error?
    func perform(_ action: FlagExplainAction) async throws {
        if let performError { throw performError }
        performed.append(action)
    }
}

@MainActor
final class AppStateTests: XCTestCase {

    private func makeState(_ stub: StubDaemonClient) -> (AppState, NSMutableArray) {
        let state = AppState(client: stub)
        let notifications = NSMutableArray()
        state.notify = { notifications.add($0.id) }
        return (state, notifications)
    }

    private func flag(_ id: String, _ severity: Int = 3) -> FlagModel {
        FlagModel(id: id, rule: "proxy-secret-leak", severity: severity, ts: "", pid: 1,
                  agent: "claude", evidence: [.legacy("e")])
    }

    func testAgentRootsFiltersToTreeRoots() async {
        let stub = StubDaemonClient()
        stub.status = StatusResponse(
            running: true, uptime: "1m", activeAgents: 1,
            agents: [
                AgentSummaryModel(pid: 500, name: "cursor", rootPid: 500),
                AgentSummaryModel(pid: 501, name: "cursor", rootPid: 500),
                AgentSummaryModel(pid: 502, name: "cursor", rootPid: 500),
            ],
            proxyEnabled: false, proxyPort: 0, uninspectedEgress: 0,
            firewallStats: nil, trackedProcesses: 3)
        let (state, _) = makeState(stub)
        await state.performFetch()
        XCTAssertEqual(state.agentRoots.map(\.pid), [500])
        XCTAssertEqual(state.activeAgentCount, 1)      // status field, not array length
        XCTAssertEqual(state.trackedProcessCount, 3)
    }

    func testFetchSurfacesMachineHeadroom() async {
        let stub = StubDaemonClient()
        stub.resources = ResourceSnapshotModel(host: HostPressureModel(
            totalMemoryBytes: 16 * 1024 * 1024 * 1024,
            availableMemoryBytes: 4 * 1024 * 1024 * 1024,
            agentMemoryBytes: 3 * 1024 * 1024 * 1024,
            nonAgentMemoryBytes: 9 * 1024 * 1024 * 1024,
            memoryPressure: "normal", thermalState: "nominal",
            headroomScore: 25, capacity: "constrained"))
        let (state, _) = makeState(stub)

        await state.performFetch()

        XCTAssertEqual(state.resources?.host?.availableMemoryBytes, 4 * 1024 * 1024 * 1024)
        XCTAssertEqual(state.resources?.host?.capacity, "constrained")
    }

    func testResourceInterventionTransitionNotifiesAfterBaseline() async {
        let stub = StubDaemonClient()
        stub.resources = ResourceSnapshotModel(host: nil, sessions: [
            ResourceSessionModel(key: "s1", name: "codex", control: ResourceSessionControlModel(state: "grace"))
        ])
        let state = AppState(client: stub)
        var notices: [ResourceInterventionNotice] = []
        state.notifyResource = { notices.append($0) }

        await state.performFetch()
        XCTAssertTrue(notices.isEmpty)

        stub.resources = ResourceSnapshotModel(host: nil, sessions: [
            ResourceSessionModel(key: "s1", name: "codex", control: ResourceSessionControlModel(
                state: "approval-required", pendingID: "resource-1", nextAction: "pause"))
        ])
        await state.performFetch()

        XCTAssertEqual(notices.count, 1)
        XCTAssertEqual(notices[0].sessionKey, "s1")
        XCTAssertEqual(notices[0].state, "approval-required")
        XCTAssertEqual(notices[0].action, "pause")
    }

	func testInitialResourceApprovalNotifiesImmediately() async {
		let stub = StubDaemonClient()
		stub.resources = ResourceSnapshotModel(host: nil, sessions: [
			ResourceSessionModel(key: "s1", name: "codex", control: ResourceSessionControlModel(
				state: "approval-required", pendingID: "resource-1", nextAction: "pause"))
		])
		let state = AppState(client: stub)
		var notices: [ResourceInterventionNotice] = []
		state.notifyResource = { notices.append($0) }

		await state.performFetch()

		XCTAssertEqual(notices.count, 1)
		XCTAssertEqual(notices[0].action, "pause")
	}

    func testAgentRootsFallbackWithoutRootPid() async {
        // Older daemon (no root_pid): every row is its own root.
        let stub = StubDaemonClient()
        stub.status = StatusResponse(
            running: true, uptime: "1m", activeAgents: 2,
            agents: [AgentSummaryModel(pid: 1, name: "claude"), AgentSummaryModel(pid: 2, name: "cursor")],
            proxyEnabled: false, proxyPort: 0, uninspectedEgress: 0, firewallStats: nil)
        let (state, _) = makeState(stub)
        await state.performFetch()
        XCTAssertEqual(state.agentRoots.count, 2)
        XCTAssertEqual(state.trackedProcessCount, 2) // falls back to array length
    }

    func testFirstFetchSeedsBaselineWithoutNotifying() async {
        let stub = StubDaemonClient()
        stub.flags = [flag("old-1"), flag("old-2")]
        let (state, notifications) = makeState(stub)
        await state.performFetch()
        // Days-old flags on launch must NOT storm the user with banners.
        XCTAssertEqual(notifications.count, 0)
        XCTAssertTrue(state.connected)
        XCTAssertEqual(state.flags.count, 2)
    }

    func testNewFlagsAfterBaselineNotifyOnce() async {
        let stub = StubDaemonClient()
        stub.flags = [flag("old-1")]
        let (state, notifications) = makeState(stub)
        await state.performFetch()
        XCTAssertEqual(notifications.count, 0)

        stub.flags = [flag("old-1"), flag("new-1")]
        await state.performFetch()
        XCTAssertEqual(notifications.count, 1)
        XCTAssertEqual(notifications[0] as? String, "new-1")

        // Same flag id again → no duplicate notification.
        await state.performFetch()
        XCTAssertEqual(notifications.count, 1)
    }

    func testLowSeverityFlagsNeverNotify() async {
        let stub = StubDaemonClient()
        stub.flags = []
        let (state, notifications) = makeState(stub)
        await state.performFetch()
        stub.flags = [flag("low", 1)]
        await state.performFetch()
        XCTAssertEqual(notifications.count, 0)
    }

    func testWarningSeveritySilentUnderDefaultPolicy() async {
        // Default bar is severity 3: a sev-2 warning queues in the UI but
        // does not page — the keychain-storm fix.
        let stub = StubDaemonClient()
        stub.flags = []
        let (state, notifications) = makeState(stub)
        await state.performFetch()
        stub.flags = [flag("warn-1", 2)]
        await state.performFetch()
        XCTAssertEqual(notifications.count, 0)
    }

    func testOverrideAlwaysNotifiesBelowBar() async {
        let stub = StubDaemonClient()
        stub.notifyRules = NotifyRulesResponse(defaultMinSeverity: 3, overrides: ["keychain-access": true])
        stub.flags = []
        let (state, notifications) = makeState(stub)
        await state.performFetch()
        stub.flags = [FlagModel(id: "kc-1", rule: "keychain-access", severity: 1, ts: "", pid: 1,
                                agent: "codex", evidence: [.legacy("e")])]
        await state.performFetch()
        XCTAssertEqual(notifications.count, 1)
    }

    func testOverrideNeverSuppressesCritical() async {
        let stub = StubDaemonClient()
        stub.notifyRules = NotifyRulesResponse(defaultMinSeverity: 3, overrides: ["proxy-secret-leak": false])
        stub.flags = []
        let (state, notifications) = makeState(stub)
        await state.performFetch()
        stub.flags = [flag("crit-1", 3)]
        await state.performFetch()
        XCTAssertEqual(notifications.count, 0)
    }

    func testSetNotifyOverrideAppliesLocallyAndPersists() async {
        let stub = StubDaemonClient()
        let (state, _) = makeState(stub)
        await state.performFetch()

        await state.setNotifyOverride(rule: "keychain-access", notify: false)
        XCTAssertEqual(state.notifyOverrides["keychain-access"], false)
        XCTAssertEqual(stub.setNotifyRuleCalls.count, 1)
        XCTAssertEqual(stub.setNotifyRuleCalls[0].rule, "keychain-access")
        XCTAssertEqual(stub.setNotifyRuleCalls[0].notify, false)

        // shouldNotify honors the local override immediately.
        XCTAssertFalse(state.shouldNotify(for: FlagModel(id: "x", rule: "keychain-access", severity: 3,
                                                         ts: "", pid: 1, agent: "codex", evidence: [])))

        // Clearing returns to the default bar.
        await state.setNotifyOverride(rule: "keychain-access", notify: nil)
        XCTAssertNil(state.notifyOverrides["keychain-access"])
        XCTAssertEqual(stub.setNotifyRuleCalls.count, 2)
        XCTAssertNil(stub.setNotifyRuleCalls[1].notify ?? nil)
    }

// Per-workspace notification scopes are the strongest tier: a scope beats the
// per-rule override and the default, matched by path prefix, longest first.
func testWorkspaceScopeBeatsRuleOverrideAndDefault() async {
    let stub = StubDaemonClient()
    stub.notifyRules = NotifyRulesResponse(
        defaultMinSeverity: 3,
        overrides: ["proxy-secret-leak": false],       // rule says never
        scopes: [NotifyScopeModel(workspace: "/Users/dev/work/prod", rule: "proxy-secret-leak", notify: true)])
    stub.flags = []
    let (state, _) = makeState(stub)
    await state.performFetch()

    // In the scoped workspace: the scope wins -> pages despite the rule "never".
    let scoped = FlagModel(id: "f1", rule: "proxy-secret-leak", severity: 3, ts: "", pid: 1,
                           agent: "claude", evidence: [], workspace: "/Users/dev/work/prod/api")
    XCTAssertTrue(state.shouldNotify(for: scoped))
    // Outside the scope: the per-rule override still applies (never).
    let outside = FlagModel(id: "f2", rule: "proxy-secret-leak", severity: 3, ts: "", pid: 1,
                            agent: "claude", evidence: [], workspace: "/Users/dev/other")
    XCTAssertFalse(state.shouldNotify(for: outside))
    // No workspace (older daemon): falls through to the rule override.
    let noWS = FlagModel(id: "f3", rule: "proxy-secret-leak", severity: 3, ts: "", pid: 1,
                         agent: "claude", evidence: [])
    XCTAssertFalse(state.shouldNotify(for: noWS))
}

    func testRetriageFeedbackLifecycle() async {
        let stub = StubDaemonClient()
        stub.flags = [flag("rt-1", 3)]
        let (state, _) = makeState(stub)
        await state.performFetch()

        // Request marks the flag pending — the sheet shows progress.
        await state.retriageFlagWithFeedback(flag("rt-1", 3))
        XCTAssertNotNil(state.pendingRetriage["rt-1"])

        // Same verdict still → still pending (present ≠ landed).
        await state.performFetch()
        XCTAssertNotNil(state.pendingRetriage["rt-1"])

        // Fresh verdict → pending clears with a "verdict updated" notice.
        stub.flags = [FlagModel(id: "rt-1", rule: "proxy-secret-leak", severity: 3, ts: "", pid: 1,
                                agent: "claude", evidence: [.legacy("e")],
                                advisor: AdvisorVerdictModel(assessment: "benign", confidence: 0.9,
                                                             rationale: "routine vendor traffic", suggestedAction: "none"))]
        await state.performFetch()
        XCTAssertNil(state.pendingRetriage["rt-1"])
        XCTAssertEqual(state.advisorNotice, "Advisor verdict updated for proxy-secret-leak")
    }

    func testRetriageTimeoutProducesHonestNotice() async {
        let stub = StubDaemonClient()
        stub.flags = [flag("rt-2", 3)]
        let (state, _) = makeState(stub)
        await state.performFetch()
        await state.retriageFlagWithFeedback(flag("rt-2", 3))
        state.agePendingRetriageForTesting(id: "rt-2")

        await state.performFetch()
        XCTAssertNil(state.pendingRetriage["rt-2"])
        XCTAssertTrue(state.advisorNotice?.contains("didn't answer") == true,
                      "timeout must explain itself, got: \(state.advisorNotice ?? "nil")")
    }

    func testDismissFlagLeavesUnactedList() async {
        let stub = StubDaemonClient()
        stub.flags = [flag("d-1", 3), flag("d-2", 3)]
        let (state, _) = makeState(stub)
        await state.performFetch()
        XCTAssertEqual(state.unactedFlags.count, 2)

        await state.dismissFlag(flag("d-1", 3))
        // Local echo: the dismissed flag stops needing action immediately.
        XCTAssertEqual(state.unactedFlags.map(\.id), ["d-2"])
    }

    func testInformationalFlagsNeverDemandAction() async {
        // Severity-1 (routine keychain-db opens) queues silently — it must
        // not occupy the popover's needs-a-decision list.
        let stub = StubDaemonClient()
        stub.flags = [flag("kc-info", 1), flag("warn", 2)]
        let (state, _) = makeState(stub)
        await state.performFetch()
        XCTAssertEqual(state.unactedFlags.map(\.id), ["warn"])
    }

    func testTransportErrorClearsAllDaemonState() async {
        let stub = StubDaemonClient()
        stub.flags = [flag("f1")]
        let (state, _) = makeState(stub)
        await state.performFetch()
        XCTAssertTrue(state.connected)
        XCTAssertFalse(state.flags.isEmpty)
        // Critical posture and a pending guard: both must survive one
        // tolerated failure and be dropped, like everything else, on the
        // second — otherwise needsAttention can keep the critical icon lit,
        // and the popover can keep exposing a guard mutation button, while
        // disconnected.
        state.seedPostureForTesting(
            PostureModel(state: "critical", needsYou: 1, summary: "1 item needs you", connected: true),
            pendingGuard: GuardPending(id: "g1", agent: "claude", tool: "Read", path: "/p/.env",
                                       ruleID: "env-files", ts: "", scopeText: nil, advisor: nil))
        XCTAssertTrue(state.needsAttention)

        stub.statusError = DaemonClientError.transport("daemon gone")
        await state.performFetch()
        // ONE transport failure is ambiguous (a slow /status join measured
        // 2–4s with ~400 live pids, past the socket timeout) — the UI must
        // not flap to Disconnected on it. It surfaces the error but keeps
        // the last-known state and the connected posture.
        XCTAssertTrue(state.connected, "a single timeout must not flip to Disconnected")
        XCTAssertNotNil(state.lastError)
        XCTAssertNotNil(state.posture, "one tolerated failure must not drop posture")
        XCTAssertNotNil(state.pendingGuard, "one tolerated failure must not drop the pending guard")

        // Second consecutive transport failure: really gone. Drop everything.
        await state.performFetch()
        XCTAssertFalse(state.connected)
        XCTAssertTrue(state.flags.isEmpty)
        XCTAssertTrue(state.guardRules.isEmpty)
        XCTAssertNil(state.status)
        XCTAssertNil(state.posture)
        XCTAssertNil(state.pendingGuard)
        XCTAssertFalse(state.needsAttention)
        XCTAssertNotNil(state.lastError)
    }

    func testSuccessResetsTransportFailureStreak() async {
        let stub = StubDaemonClient()
        let (state, _) = makeState(stub)
        await state.performFetch() // baseline: connected

        stub.statusError = DaemonClientError.transport("blip")
        await state.performFetch() // failure #1 — tolerated
        XCTAssertTrue(state.connected)

        stub.statusError = nil
        await state.performFetch() // recovers
        XCTAssertTrue(state.connected)

        stub.statusError = DaemonClientError.transport("blip again, much later")
        await state.performFetch() // a NEW single failure — also tolerated
        XCTAssertTrue(state.connected)
        XCTAssertNotNil(state.lastError) // …but honestly surfaced
    }

    func testDecodeErrorKeepsConnected() async {
        let stub = StubDaemonClient()
        let (state, _) = makeState(stub)
        await state.performFetch()
        XCTAssertTrue(state.connected)

        stub.statusError = DaemonClientError.decode("garbage payload")
        await state.performFetch()
        // A daemon answering garbage is UP and misbehaving — not "Disconnected".
        XCTAssertTrue(state.connected)
        XCTAssertTrue(state.lastError?.contains("decode error") ?? false)
    }

    func testGuardDecodeFailureIsSurfacedNotSwallowed() async {
        let stub = StubDaemonClient()
        stub.guardError = DaemonClientError.decode("bad guard payload")
        let (state, _) = makeState(stub)
        await state.performFetch()
        XCTAssertTrue(state.connected) // the rest of the daemon is fine
        XCTAssertTrue(state.lastError?.contains("guard check failed") ?? false)
    }

    func testPausedFetchIsANoOp() async {
        let stub = StubDaemonClient()
        let (state, _) = makeState(stub)
        state.isPaused = true
        state.fetch()
        XCTAssertFalse(state.connected)
    }

    func testResumeReseedsNotificationBaseline() async {
        let stub = StubDaemonClient()
        let (state, notifications) = makeState(stub)
        await state.performFetch() // baseline seed
        XCTAssertEqual(notifications.count, 0)

        // Flags arrive, then the user pauses: more flags accrue unseen.
        stub.flags = [flag("during-pause-1"), flag("during-pause-2")]
        state.isPaused = true
        state.togglePause() // resume
        XCTAssertFalse(state.isPaused)
        await state.performFetch()
        // The whole pause-window batch is baseline, not news — no banner storm.
        XCTAssertEqual(notifications.count, 0)
        XCTAssertEqual(state.flags.count, 2)
    }

    func testGuardPromptStillFlowsWhilePaused() async {
        let stub = StubDaemonClient()
        stub.pending = [GuardPending(id: "g1", agent: "claude", tool: "Read",
                                     path: "/Users/x/.ssh/id_ed25519", ruleID: "ssh-keys",
                                     ts: "", scopeText: nil, advisor: nil)]
        let (state, _) = makeState(stub)
        state.testHookSkipPromptDialog = true // NSAlert.runModal is untestable
        state.isPaused = true
        state.fetch()
        // Give the detached poll task a beat; the prompt path must be live
        // even with alerts silenced — agents block on this decision.
        for _ in 0..<50 {
            if state.promptingIDForTesting == "g1" { break }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertEqual(state.promptingIDForTesting, "g1")
    }

    // MARK: - Agent tree grouping

    private func agent(_ pid: Int32, root: Int32? = nil, ppid: Int32? = nil,
                       started: String? = nil, seen: String? = nil, rss: UInt64? = nil,
                       cpu: Double? = nil) -> AgentSummaryModel {
        AgentSummaryModel(pid: pid, name: "claude", rootPid: root ?? pid,
                          ppid: ppid, startedAt: started, lastSeenAt: seen, rssBytes: rss,
                          cpuPercent: cpu)
    }

    func testAgentRowsGroupTreesAndSortByLastActivity() {
        let stub = StubDaemonClient()
        // Session A: root 100 + children 101, 102. Session B: root 200 alone.
        stub.status.agents = [
            agent(100, root: 100, ppid: 1, started: "2026-09-11T10:00:00Z", seen: "2026-09-11T12:00:00Z", rss: 100),
            agent(101, root: 100, ppid: 100, started: "2026-09-11T10:01:00Z", seen: "2026-09-11T11:30:00Z", rss: 50),
            agent(102, root: 100, ppid: 100, started: "2026-09-11T10:02:00Z", seen: "2026-09-11T12:00:00Z", rss: 70),
            agent(200, root: 200, ppid: 1, started: "2026-09-11T09:00:00Z", seen: "2026-09-11T11:00:00Z", rss: 30),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)

        let rows = state.agentRows(sortedBy: .lastActivity)
        // Roots first within ordering; most-recent family first (tree 100 @
        // 12:00 beats tree 200 @ 11:00).
        XCTAssertEqual(rows.map(\.agent.pid), [100, 101, 102, 200])
        XCTAssertEqual(rows.map(\.depth), [0, 1, 1, 0])
        // Root 100 aggregates family memory: 100 + 50 + 70.
        XCTAssertEqual(rows[0].familyRSSBytes, 220)
        XCTAssertEqual(rows[0].childCount, 2)
        // Children carry their own RSS, no family aggregate.
        XCTAssertNil(rows[1].familyRSSBytes)
        XCTAssertEqual(rows[1].agent.rssBytes, 50)
    }

    func testAgentRowsSortByCreatedIsChronological() {
        let stub = StubDaemonClient()
        stub.status.agents = [
            agent(200, root: 200, ppid: 1, started: "2026-09-11T09:00:00Z"),
            agent(100, root: 100, ppid: 1, started: "2026-09-11T10:00:00Z"),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        // Oldest session first: reading top-down = spawn order story.
        XCTAssertEqual(state.agentRows(sortedBy: .created).map(\.agent.pid), [200, 100])
    }

    func testAgentRowsSortByMemoryFamiliesAggregate() {
        let stub = StubDaemonClient()
        stub.status.agents = [
            agent(200, root: 200, ppid: 1, rss: 900),
            agent(100, root: 100, ppid: 1, rss: 100),
            agent(101, root: 100, ppid: 100, rss: 950),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        // Tree 100 totals 1050 > tree 200's 900 → 100 first.
        let rows = state.agentRows(sortedBy: .memory)
        XCTAssertEqual(rows.first?.agent.pid, 100)
        XCTAssertEqual(rows.first?.familyRSSBytes, 1050)
    }

    func testAgentRowsSortByImpactAndAggregateFamilyCPU() {
        let gib = UInt64(1024 * 1024 * 1024)
        let stub = StubDaemonClient()
        stub.status.agents = [
            agent(100, root: 100, ppid: 1, rss: gib, cpu: 80),
            agent(101, root: 100, ppid: 100, rss: 64, cpu: 70),
            agent(200, root: 200, ppid: 1, rss: 3 * gib, cpu: 0),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)

        let rows = state.agentRows(sortedBy: .impact)
        XCTAssertEqual(rows.first?.agent.pid, 100)
        XCTAssertEqual(rows.first?.familyCPUPercent, 150)
    }

    func testAgentRowsKeepUnavailableFamilyCPUUnknown() {
        let stub = StubDaemonClient()
        stub.status.agents = [agent(100, root: 100, ppid: 1, rss: 100)]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)

        XCTAssertNil(state.agentRows(sortedBy: .impact).first?.familyCPUPercent)
    }

    func testAgentRowsTreatsOrphanChildAsStillInTree() {
        // A child whose parent pid left the table but root_pid still points
        // at the family stays grouped — that's exactly the subagent case.
        let stub = StubDaemonClient()
        stub.status.agents = [
            agent(100, root: 100, ppid: 1),
            agent(102, root: 100, ppid: 999), // spawned by a now-dead middle proc
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        let rows = state.agentRows(sortedBy: .created)
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0].agent.pid, 100)
        XCTAssertEqual(rows[1].agent.pid, 102)
        XCTAssertEqual(rows[1].depth, 1)
    }
}

@MainActor
final class WeeklyDigestTests: XCTestCase {
    func testShouldSendOnlyMondayAtNineOncePerWeek() {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "UTC")!
        // Monday 2026-09-07 is a Monday (verified: 2026-09-07 was a Monday).
        let mon9 = cal.date(from: DateComponents(year: 2026, month: 9, day: 7, hour: 9, minute: 30))!
        let mon8 = cal.date(from: DateComponents(year: 2026, month: 9, day: 7, hour: 8, minute: 59))!
        let tue9 = cal.date(from: DateComponents(year: 2026, month: 9, day: 8, hour: 9, minute: 0))!

        XCTAssertTrue(AppState.shouldSendWeeklyDigest(now: mon9, lastSentWeek: nil, calendar: cal))
        XCTAssertFalse(AppState.shouldSendWeeklyDigest(now: mon8, lastSentWeek: nil, calendar: cal))
        XCTAssertFalse(AppState.shouldSendWeeklyDigest(now: tue9, lastSentWeek: nil, calendar: cal))
        // Already sent this ISO week.
        let key = AppState.currentWeekKey(now: mon9, calendar: cal)
        XCTAssertFalse(AppState.shouldSendWeeklyDigest(now: mon9, lastSentWeek: key, calendar: cal))
    }

    func testDigestTextPluralization() {
        XCTAssertEqual(AppState.weeklyDigestText(flags7d: 3, blockedLeaks: 1, approvals: 2, openIncidents: 0),
                       "3 flags · 1 blocked leak · 2 allowlist approvals · 0 open incidents")
        XCTAssertEqual(AppState.weeklyDigestText(flags7d: 1, blockedLeaks: 2, approvals: 1, openIncidents: 1),
                       "1 flag · 2 blocked leaks · 1 allowlist approval · 1 open incident")
    }
}


// MARK: - Harness grouping (provider → sessions → subagents)

@MainActor
final class HarnessGroupTests: XCTestCase {
    private func agent(_ pid: Int32, name: String, root: Int32, ppid: Int32,
                       started: String = "", seen: String = "", rss: UInt64? = nil) -> AgentSummaryModel {
        AgentSummaryModel(pid: pid, name: name, rootPid: root, ppid: ppid,
                          startedAt: started, lastSeenAt: seen, rssBytes: rss)
    }

    func testHarnessGroupsSplitByProvider() {
        let stub = StubDaemonClient()
        stub.status.agents = [
            agent(100, name: "claude", root: 100, ppid: 1, seen: "2026-09-11T12:00:00Z"),
            agent(101, name: "claude", root: 100, ppid: 100),
            agent(200, name: "cursor", root: 200, ppid: 1, seen: "2026-09-11T11:00:00Z"),
            agent(300, name: "codex", root: 300, ppid: 1),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        let groups = state.harnessGroups(sortedBy: .lastActivity)
        // 3 harness groups from 4 processes.
        XCTAssertEqual(groups.map(\.name), ["claude", "cursor", "codex"])
        let claude = groups[0]
        XCTAssertEqual(claude.sessionCount, 1)
        XCTAssertEqual(claude.processCount, 2)
        // Group aggregates family memory.
        if let rss = claude.totalRSSBytes { XCTAssertEqual(Int(rss), 0) }
        XCTAssertEqual(groups[0].trees.count, 1)
        XCTAssertEqual(groups[0].trees[0].1.count, 1) // 1 subagent under the session
    }

    func testMultipleSessionsWithinOneHarness() {
        let stub = StubDaemonClient()
        stub.status.agents = [
            agent(100, name: "claude", root: 100, ppid: 1, seen: "2026-09-11T12:00:00Z"),
            agent(150, name: "claude", root: 150, ppid: 1, seen: "2026-09-11T11:00:00Z"),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        let groups = state.harnessGroups(sortedBy: .lastActivity)
        XCTAssertEqual(groups.count, 1)
        XCTAssertEqual(groups[0].sessionCount, 2)
        // Most-recent session first within the group.
        XCTAssertEqual(groups[0].trees.first?.0.pid, 100)
    }
}

final class SessionBoardTests: XCTestCase {
    func testCwdLeafIsProjectFolder() {
        let a = AgentSummaryModel(pid: 1, name: "claude", cwd: "/Users/dev/workspace/api-service")
        XCTAssertEqual(a.cwdLeaf, "api-service")
    }

    func testCwdLeafFallsBackToHarnessName() {
        let a = AgentSummaryModel(pid: 1, name: "codex")
        XCTAssertEqual(a.cwdLeaf, "codex")
    }
}

@MainActor
final class SessionBoardRowTests: XCTestCase {
    private func agent(_ pid: Int32, name: String, root: Int32, ppid: Int32,
                       cwd: String? = nil, seen: String = "", rss: UInt64? = nil,
                       cpu: Double? = nil) -> AgentSummaryModel {
        AgentSummaryModel(pid: pid, name: name, cwd: cwd, rootPid: root, ppid: ppid,
                          lastSeenAt: seen, rssBytes: rss, cpuPercent: cpu)
    }

    func testSessionBoardRowsAreRootsOnlySortedByActivity() {
        let stub = StubDaemonClient()
        stub.status.agents = [
            agent(5822, name: "claude", root: 5821, ppid: 5821, rss: 50),
            agent(5821, name: "claude", root: 5821, ppid: 1,
                  cwd: "/Users/dev/workspace/api-service",
                  seen: "2026-09-11T12:00:00Z", rss: 100),
            agent(6033, name: "cursor", root: 6033, ppid: 1,
                  cwd: "/Users/dev/projects/web-app",
                  seen: "2026-09-11T11:00:00Z", rss: 10),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        let rows = state.sessionBoardRows(sortedBy: .lastActivity)
        XCTAssertEqual(rows.map(\.agent.pid), [5821, 6033])
        XCTAssertEqual(rows[0].agent.cwdLeaf, "api-service")
        XCTAssertEqual(rows[0].familyRSSBytes, 150)
        XCTAssertEqual(rows[0].childCount, 1)
        XCTAssertEqual(rows[1].agent.cwdLeaf, "web-app")
    }

    func testSessionBoardRowsDoesNotCapAtSix() {
        let stub = StubDaemonClient()
        stub.status.agents = (1...8).map { i in
            agent(Int32(i), name: "claude", root: Int32(i), ppid: 1,
                  cwd: "/tmp/p\(i)", seen: "2026-09-11T12:00:0\(i)Z")
        }
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        XCTAssertEqual(state.sessionBoardRows(sortedBy: .lastActivity).count, 8)
    }

    func testSessionBoardRowsPrefersDaemonTrees() {
        let stub = StubDaemonClient()
        stub.status.agents = [
            agent(99, name: "should-ignore", root: 99, ppid: 1, cwd: "/tmp/wrong"),
        ]
        stub.status.trees = [
            AgentTreeModel(
                root: agent(10, name: "claude", root: 10, ppid: 1, cwd: "/tmp/proj", seen: "2026-09-15T12:00:00Z", rss: 100),
                children: [agent(11, name: "claude", root: 10, ppid: 10, rss: 50)],
                rssBytes: 150,
                lastSeenAt: "2026-09-15T12:00:00Z",
                cpuPercent: 42),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        let rows = state.sessionBoardRows(sortedBy: .lastActivity)
        XCTAssertEqual(rows.map(\.agent.pid), [10])
        XCTAssertEqual(rows[0].agent.cwdLeaf, "proj")
        XCTAssertEqual(rows[0].familyRSSBytes, 150)
        XCTAssertEqual(rows[0].familyCPUPercent, 42)
        XCTAssertEqual(rows[0].childCount, 1)
    }

    func testMonitorVendorKeyIDsSkipsBlockAndNonVendor() {
        let stub = StubDaemonClient()
        stub.status.firewallStats = [
            "openai-key": RuleStatModel(mode: "monitor", type: "vendor-key"),
            "anthropic-key": RuleStatModel(mode: "block", type: "vendor-key"),
            "aws-key": RuleStatModel(mode: "monitor", type: "cloud-key"),
        ]
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        XCTAssertEqual(state.monitorVendorKeyIDs, ["openai-key"])
        XCTAssertFalse(state.showFleetPanel)
    }

    func testShowFleetPanelWhenConfigured() {
        let stub = StubDaemonClient()
        stub.status.fleetConfigured = true
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        XCTAssertTrue(state.showFleetPanel)
    }

}

// MARK: - SSE chunked-body decoding (the reconnect-loop fix)

@MainActor
final class SSEDechunkerTests: XCTestCase {
    func testDechunksAcrossReadBoundaries() {
        var d = ChunkedBodyDechunker()
        d.isChunked = true
        // Two chunks split at hostile boundaries.
        let body = "8\r\n: ping\n\n\r\n12\r\n: hello world!!!\n\n\r\n0\r\n\r\n"
        let bytes = Array(body.utf8)
        var out: [String] = []
        var i = 0
        while i < bytes.count {
            let take = min(7, bytes.count - i) // tiny reads, mid-frame splits
            for piece in d.append(Data(bytes[i..<i+take])) {
                out.append(String(decoding: piece, as: UTF8.self))
            }
            i += take
        }
        XCTAssertEqual(out.joined(), ": ping\n\n: hello world!!!\n\n")
    }

    func testPassthroughWhenNotChunked() {
        var d = ChunkedBodyDechunker()
        d.isChunked = false
        let out = d.append(Data(": raw\n\n".utf8))
        XCTAssertEqual(out.map { String(decoding: $0, as: UTF8.self) }.joined(), ": raw\n\n")
    }

    func testMalformedSizeResetsInsteadOfGarbage() {
        var d = ChunkedBodyDechunker()
        d.isChunked = true
        _ = d.append(Data("zzz\r\n".utf8)) // bad hex → reset
        let out = d.append(Data("5\r\nhello\r\n0\r\n\r\n".utf8))
        XCTAssertEqual(out.map { String(decoding: $0, as: UTF8.self) }.joined(), "hello")
    }
}


// MARK: - Advisor persistence (mode/endpoint/model must survive restarts)

final class AdvisorConfigReaderTests: XCTestCase {
    func testReadsManagedModel() {
        let yaml = """
        advisor:
          enabled: true
          managed: true
          managed_model: "qwen3.8:27b-mlx"
        """
        let c = SetupManager.advisorConfig(yaml)
        XCTAssertEqual(c.mode, "managed")
        XCTAssertEqual(c.model, "qwen3.8:27b-mlx")
    }

    func testReadsExistingEndpoint() {
        let yaml = """
        other: 1
        advisor:
          enabled: true
          managed: false
          endpoint: "http://127.0.0.1:11434"
          model: "qwen3.8:27b-mlx"
        """
        let c = SetupManager.advisorConfig(yaml)
        XCTAssertEqual(c.mode, "existing")
        XCTAssertEqual(c.endpoint, "http://127.0.0.1:11434")
        XCTAssertEqual(c.model, "qwen3.8:27b-mlx")
    }

    func testMissingAdvisorBlockIsNilNotFalsePositive() {
        let c = SetupManager.advisorConfig("other: 1\n")
        XCTAssertNil(c.mode)
        XCTAssertNil(c.model)
    }
}


// MARK: - Provider toggles (disabled_agents)

final class DisabledAgentsTests: XCTestCase {
    func testReadsEmptyWhenAbsent() {
        XCTAssertEqual(SetupManager.disabledAgents("advisor:\n  enabled: true\n"), [])
    }

    func testReadsList() {
        let yaml = """
        disabled_agents:
          - cursor
          - codex
        advisor:
          enabled: true
        """
        XCTAssertEqual(SetupManager.disabledAgents(yaml), ["cursor", "codex"])
    }

    func testWriteAppendsAtTopPreservingRest() {
        let yaml = "# comment\nadvisor:\n  enabled: true\n"
        let out = SetupManager.setDisabledAgents(yaml, disabled: ["ollama"])
        XCTAssertTrue(out.contains("disabled_agents:\n  - ollama"))
        XCTAssertTrue(out.contains("advisor:\n  enabled: true"))
    }

    func testWriteReplacesExistingBlock() {
        let yaml = "disabled_agents:\n  - cursor\nadvisor:\n  enabled: true\n"
        let out = SetupManager.setDisabledAgents(yaml, disabled: ["opencode"])
        XCTAssertTrue(out.contains("- opencode"))
        XCTAssertFalse(out.contains("- cursor"))
        XCTAssertEqual(SetupManager.disabledAgents(out), ["opencode"])
    }

    func testEmptyWriteRemovesBlock() {
        let yaml = "disabled_agents:\n  - cursor\nother: 1\n"
        let out = SetupManager.setDisabledAgents(yaml, disabled: [])
        XCTAssertFalse(out.contains("disabled_agents"))
        XCTAssertTrue(out.contains("other: 1"))
    }
}


// MARK: - Flag grouping (identical repeats are ONE decision)
