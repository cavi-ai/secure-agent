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
        XCTAssertFalse(state.connected)
        XCTAssertTrue(state.flags.isEmpty)
        XCTAssertTrue(state.guardRules.isEmpty)
        XCTAssertNil(state.status)
        XCTAssertNotNil(state.lastError)
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
