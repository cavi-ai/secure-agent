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

    func fetchStatus() async throws -> StatusResponse {
        if let statusError { throw statusError }
        return status
    }
    func fetchFlags(limit: Int) async throws -> [FlagModel] { flags }
    func fetchIncidents(limit: Int) async throws -> [IncidentReportModel] { [] }
    func fetchIncidentMarkdown(id: String) async throws -> String { "" }
    func fetchEvents(limit: Int) async throws -> [EventModel] { [] }
    func fetchEventsFor(pid: Int32, limit: Int) async throws -> [EventModel] { [] }
    func allowlistAdd(agent: String, host: String) async throws { }
    func guardPathAllowAdd(agent: String, ruleID: String, path: String) async throws { }
    func retriageFlag(id: String) async throws { }
    func fetchGuardPathAllows() async throws -> [GuardPathAllowModel] { [] }
    func deleteGuardPathAllow(agent: String, ruleID: String, path: String) async throws { }
    func muteAdd(rule: String, host: String) async throws { }
    func fetchGuardRules() async throws -> [GuardRuleModel] { [] }
    func fetchGuardPending() async throws -> [GuardPending] {
        if let guardError { throw guardError }
        return pending
    }
    func resolveGuard(_ req: GuardResolveRequest) async throws {}
    func killProcess(pid: Int32) async throws -> Bool { true }
    func deleteGuardRule(agent: String, ruleID: String) async throws {}
    func setFirewallMode(rule: String, mode: String) async throws {}
    func fetchAdvisorDiscover() async throws -> AdvisorDiscovery {
        AdvisorDiscovery(servers: [], managedModels: [])
    }
    func fetchRollup(hours: Int) async throws -> [RollupPointModel] { [] }
    func fetchAudit(limit: Int) async throws -> [AuditEntryModel] { [] }
    func streamEvents(onEvent: @escaping @Sendable (SSEFrame) -> Void) async throws {
        try await Task.sleep(nanoseconds: 60_000_000_000) // tests don't drive SSE
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
                  agent: "claude", evidence: ["e"])
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

    func testTransportErrorClearsAllDaemonState() async {
        let stub = StubDaemonClient()
        stub.flags = [flag("f1")]
        let (state, _) = makeState(stub)
        await state.performFetch()
        XCTAssertTrue(state.connected)
        XCTAssertFalse(state.flags.isEmpty)

        stub.statusError = DaemonClientError.transport("daemon gone")
        await state.performFetch()
        // ONE transport failure is ambiguous (a slow /status join measured
        // 2–4s with ~400 live pids, past the socket timeout) — the UI must
        // not flap to Disconnected on it. It surfaces the error but keeps
        // the last-known state and the connected posture.
        XCTAssertTrue(state.connected, "a single timeout must not flip to Disconnected")
        XCTAssertNotNil(state.lastError)

        // Second consecutive transport failure: really gone. Drop everything.
        await state.performFetch()
        XCTAssertFalse(state.connected)
        XCTAssertTrue(state.flags.isEmpty)
        XCTAssertTrue(state.guardRules.isEmpty)
        XCTAssertNil(state.status)
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
                                     ts: "", scopeText: nil)]
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
                       started: String? = nil, seen: String? = nil, rss: UInt64? = nil) -> AgentSummaryModel {
        AgentSummaryModel(pid: pid, name: "claude", rootPid: root ?? pid,
                          ppid: ppid, startedAt: started, lastSeenAt: seen, rssBytes: rss)
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


// MARK: - Incident evidence parsing (Little-Snitch dispositions depend on it)

final class IncidentEvidenceParsingTests: XCTestCase {
    func testFilePathOnlyExtractsPathFromProse() {
        XCTAssertEqual(
            IncidentDetailView.filePathOnly(from: "claude (pid 123) read /Users/x/.ssh/id_ed25519 at 2026-09-11T12:00:00Z"),
            "/Users/x/.ssh/id_ed25519")
    }

    func testFilePathOnlyPassesThroughNonProse() {
        XCTAssertEqual(IncidentDetailView.filePathOnly(from: "/a/b"), "/a/b")
    }

    func testConnHostPortExtractsFromProse() {
        XCTAssertEqual(
            IncidentDetailView.connHostPort(from: "then connected to api.anthropic.com:443 at 2026-09-11T12:00:01Z"),
            "api.anthropic.com:443")
    }

    func testHostFromHostPort() {
        XCTAssertEqual(IncidentDetailView.host(from: "api.anthropic.com:443"), "api.anthropic.com")
        XCTAssertEqual(IncidentDetailView.host(from: "[::1]:443"), "::1")
        // Bare IPv6 (no port) returned as-is — never split at the wrong colon.
        XCTAssertEqual(IncidentDetailView.host(from: "2606:4700::ac40"), "2606:4700::ac40")
    }

    func testHostFromProseConnection() {
        XCTAssertEqual(
            IncidentDetailView.host(from: IncidentDetailView.connHostPort(
                from: "then connected to 160.79.104.10:443 at 2026-09-11T12:00:01Z")),
            "160.79.104.10")
    }
}


// MARK: - Flag action sheet (actionable criticals)

final class FlagActionSheetTests: XCTestCase {
    func testHumanTitleMapsRules() {
        XCTAssertEqual(FlagActionSheet.humanTitle("sensitive-read-then-connect"), "Agent read a secret, then connected out")
        XCTAssertEqual(FlagActionSheet.humanTitle("unknown-rule"), "unknown-rule")
    }

    func testHostFromEvidence() {
        XCTAssertEqual(
            FlagActionSheet.hostIn(evidence: [
                "cursor (pid 9) read /Users/x/.env at 2026-09-11T12:00:00Z",
                "then connected to api.example.com:443 at 2026-09-11T12:00:01Z",
            ]),
            "api.example.com")
        XCTAssertNil(FlagActionSheet.hostIn(evidence: ["no connections here"]))
    }

    func testHostFromHostPortIPv6() {
        XCTAssertEqual(FlagActionSheet.hostFromHostPort("[2606:4700::1]:443"), "2606:4700::1")
        XCTAssertEqual(FlagActionSheet.hostFromHostPort("160.79.104.10:443"), "160.79.104.10")
    }

    func testTimestampInExtractsEvidenceTime() {
        XCTAssertEqual(
            FlagActionSheet.timestampIn("claude read /a at 2026-09-11T12:00:05Z"),
            "2026-09-11T12:00:05Z")
        XCTAssertEqual(FlagActionSheet.timestampIn("no time here"), "")
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


// MARK: - Advisor → action mapping (suggested_action must become a button)

@MainActor
final class AdvisorActionMappingTests: XCTestCase {
    private let flag = FlagModel(id: "f1", rule: "sensitive-read-then-connect",
                                 severity: 3, ts: "", pid: 7, agent: "cursor", evidence: [])

    func testAllowHostMapsWhenHostPresent() {
        let m = FlagActionSheet.mappedAction("allow-host", flag: flag, evidenceHost: "api.example.com")
        XCTAssertEqual(m?.kind, "allow-host")
        XCTAssertTrue(m!.title.contains("api.example.com"))
    }

    func testAllowHostNilWithoutHost() {
        XCTAssertNil(FlagActionSheet.mappedAction("allow-host", flag: flag, evidenceHost: nil))
    }

    func testAllFourActionsMap() {
        XCTAssertEqual(FlagActionSheet.mappedAction("mute-rule", flag: flag, evidenceHost: nil)?.kind, "mute-rule")
        XCTAssertEqual(FlagActionSheet.mappedAction("rotate-credentials", flag: flag, evidenceHost: nil)?.kind, "rotate")
        XCTAssertEqual(FlagActionSheet.mappedAction("kill-agent", flag: flag, evidenceHost: nil)?.kind, "kill")
    }

    func testUnknownActionMapsToNothing() {
        XCTAssertNil(FlagActionSheet.mappedAction("do-something-random", flag: flag, evidenceHost: nil))
        XCTAssertNil(FlagActionSheet.mappedAction(nil, flag: flag, evidenceHost: nil))
    }
}
