import XCTest
@testable import SecureAgentMenubar

/// Served flag explain decoding, SSE-typed refresh, and in-place actions.
@MainActor
final class PopoverGlanceTests: XCTestCase {

    private func liveFlags() throws -> [FlagModel] {
        try JSONDecoder().decode([FlagModel].self, from: Data(LiveFlagsFixture.json.utf8))
    }

    func testLiveFlagsDecodeExplain() throws {
        let flags = try liveFlags()
        XCTAssertEqual(flags.count, 3)
        let read = try XCTUnwrap(flags.first { $0.rule == "sensitive-read-then-connect" })
        let e = try XCTUnwrap(read.explain)
        XCTAssertEqual(e.disposition.state, "acknowledged")
        XCTAssertEqual(e.disposition.text, "Reviewed")
        XCTAssertEqual(e.disposition.why, "Agent read a secret, then connected out")
        XCTAssertFalse(e.what.isEmpty)
        XCTAssertEqual(e.actions.map(\.id), ["allow-host", "open-incident"])
        let allow = try XCTUnwrap(e.recommended)
        XCTAssertEqual(allow.id, "allow-host")
        XCTAssertEqual(allow.method, "POST")
        XCTAssertEqual(allow.path, "/allowlist")
        XCTAssertFalse(allow.consequence.isEmpty)
        XCTAssertEqual(allow.body.map { Set($0.keys) }, ["agent", "host"])

        let keychain = try XCTUnwrap(flags.first { $0.rule == "keychain-access" })
        let mute = try XCTUnwrap(keychain.explain?.actions.first { $0.id == "mute-class" })
        XCTAssertEqual(mute.body?["host"], .string("*"))
        XCTAssertNil(keychain.explain?.recommended)
    }

    /// The served body goes back to the daemon byte-for-byte in meaning.
    func testServedBodyReencodesLosslessly() throws {
        let raw = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(LiveFlagsFixture.json.utf8)) as? [[String: Any]])
        let flags = try liveFlags()
        for (row, flag) in zip(raw, flags) {
            let rawActions = try XCTUnwrap((row["explain"] as? [String: Any])?["actions"] as? [[String: Any]])
            for (rawAction, action) in zip(rawActions, flag.explain?.actions ?? []) {
                guard let rawBody = rawAction["body"] as? [String: Any] else {
                    XCTAssertNil(action.body)
                    continue
                }
                let reencoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(action.body)) as? NSDictionary
                XCTAssertEqual(reencoded, rawBody as NSDictionary)
            }
        }
        let mixed: [String: JSONValue] = ["flag_ids": .array([.string("a")]), "pid": .int(7), "x": .double(1.5),
                                          "on": .bool(true), "n": .null, "o": .object(["k": .string("v")])]
        XCTAssertEqual(try JSONDecoder().decode([String: JSONValue].self, from: JSONEncoder().encode(mixed)), mixed)
    }

    // MARK: SSE-typed refresh

    private func connectedState(_ stub: StubDaemonClient) -> AppState {
        let state = AppState(client: stub)
        state.seedForTesting(status: stub.status)
        state.streamDebounceNanos = 0
        return state
    }

    private func settle() async {
        try? await Task.sleep(nanoseconds: 150_000_000)
    }

    func testEventFramesNeverFetchFlags() async {
        let stub = StubDaemonClient()
        let state = connectedState(stub)
        for _ in 0..<100 { state.handleStreamEvent(SSEFrame(event: "event", data: "{}")) }
        state.handleStreamEvent(SSEFrame(event: "session", data: "{}"))
        await settle()
        XCTAssertEqual(stub.fetchFlagsCalls, 0)

        state.handleStreamEvent(SSEFrame(event: "flag", data: "{}"))
        await settle()
        XCTAssertEqual(stub.fetchFlagsCalls, 1)
    }

    func testStreamRefreshRouting() {
        XCTAssertEqual(AppState.streamRefresh(for: "event"), [])
        XCTAssertEqual(AppState.streamRefresh(for: "session"), [])
        XCTAssertEqual(AppState.streamRefresh(for: "incident"), [])
        XCTAssertEqual(AppState.streamRefresh(for: "flag"), [.flags, .posture])
        XCTAssertEqual(AppState.streamRefresh(for: "posture"), [.flags, .posture])
        XCTAssertEqual(AppState.streamRefresh(for: "guard-prompt"), [.flags, .guardPending])
        XCTAssertEqual(AppState.streamRefresh(for: "guard-resolved"), [.flags, .guardPending])
    }

    func testIdenticalRefetchDoesNotCallOnChange() async {
        let stub = StubDaemonClient()
        let f = FlagModel(id: "f1", rule: "keychain-access", severity: 2, ts: "", pid: 1, agent: "codex", evidence: [])
        stub.flags = [f]
        let state = connectedState(stub)
        state.seedFlagsForTesting([f])
        state.seedPostureForTesting(stub.posture)
        var changes = 0
        state.onChange = { changes += 1 }

        state.handleStreamEvent(SSEFrame(event: "flag", data: "{}"))
        await settle()
        XCTAssertEqual(stub.fetchFlagsCalls, 1)
        XCTAssertEqual(changes, 0, "an identical refetch must not re-render the popover")

        stub.flags = [f.acknowledgedCopy()]
        state.handleStreamEvent(SSEFrame(event: "flag", data: "{}"))
        await settle()
        XCTAssertEqual(changes, 1)
        XCTAssertEqual(state.flags.first?.acknowledged, true)
    }

    // MARK: act in place

    private let allowHost = FlagExplainAction(id: "allow-host", label: "Allow api.example.com for cursor",
                                              consequence: "trusted", method: "POST", path: "/allowlist",
                                              body: ["agent": .string("cursor"), "host": .string("api.example.com")],
                                              recommended: true)

    func testPerformInPlaceSendsServedActionAndRefetches() async {
        let stub = StubDaemonClient()
        let state = connectedState(stub)
        let f = FlagModel(id: "f1", rule: "sensitive-read-then-connect", severity: 3, ts: "", pid: 1,
                          agent: "cursor", evidence: [])
        await state.performInPlace(allowHost, on: f)
        XCTAssertEqual(stub.performed, [allowHost])
        XCTAssertEqual(state.inPlaceAction?.phase, .done)
        XCTAssertEqual(stub.fetchFlagsCalls, 1)
    }

    func testPerformInPlaceFailureReenablesWithError() async {
        let stub = StubDaemonClient()
        stub.performError = DaemonClientError.http(500)
        let state = connectedState(stub)
        let f = FlagModel(id: "f1", rule: "r", severity: 3, ts: "", pid: 1, agent: "cursor", evidence: [])
        await state.performInPlace(allowHost, on: f)
        XCTAssertEqual(state.inPlaceAction?.phase, .failed("daemon answered HTTP 500"))
        XCTAssertTrue(stub.performed.isEmpty)
    }

    func testPerformRefusesUnsafeRequestLine() {
        func action(_ method: String, _ path: String) -> FlagExplainAction {
            FlagExplainAction(id: "x", label: "x", consequence: "", method: method, path: path)
        }
        XCTAssertNoThrow(try DaemonClient.validate(action("POST", "/allowlist")))
        XCTAssertNoThrow(try DaemonClient.validate(action("GET", "/incidents?id=inc-1-2&format=markdown")))
        XCTAssertThrowsError(try DaemonClient.validate(action("TRACE", "/allowlist")))
        XCTAssertThrowsError(try DaemonClient.validate(action("POST", "allowlist")))
        XCTAssertThrowsError(try DaemonClient.validate(action("POST", "/x HTTP/1.1\r\nHost: evil")))
    }

    // MARK: session board memo

    func testSessionBoardRowsFollowNewStatus() {
        let state = AppState.previewAgents([AgentSummaryModel(pid: 1, name: "claude")])
        XCTAssertEqual(state.sessionBoardRows(sortedBy: .created).map(\.agent.pid), [1])
        XCTAssertEqual(state.sessionBoardRows(sortedBy: .created).map(\.agent.pid), [1])
        state.seedForTesting(status: StatusResponse(
            running: true, uptime: "1m", activeAgents: 1,
            agents: [AgentSummaryModel(pid: 2, name: "codex")],
            proxyEnabled: false, proxyPort: 0, uninspectedEgress: 0, firewallStats: nil))
        XCTAssertEqual(state.sessionBoardRows(sortedBy: .created).map(\.agent.pid), [2])
    }
}
