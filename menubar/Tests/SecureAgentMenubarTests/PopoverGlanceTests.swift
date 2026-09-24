import XCTest
@testable import SecureAgentMenubar

/// Served flag explain decoding, SSE-typed refresh, and in-place actions.
@MainActor
final class PopoverGlanceTests: XCTestCase {

    private func liveFlags() throws -> [FlagModel] {
        try JSONDecoder().decode([FlagModel].self, from: Data(FlagsExplainFixture.json.utf8))
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
        let raw = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(FlagsExplainFixture.json.utf8)) as? [[String: Any]])
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
        let f = FlagModel(id: "f1", rule: "sensitive-read-then-connect", severity: 3, ts: "", pid: 1,
                          agent: "cursor", evidence: [])
        stub.flags = [f]
        let state = connectedState(stub)
        state.seedFlagsForTesting([f])
        XCTAssertEqual(state.heroFlag?.id, "f1")

        await state.performInPlace(allowHost, on: f)

        XCTAssertEqual(stub.performed, [allowHost])
        // allow-host mutates policy only — unlike mute/dismiss it does not
        // close the flag on the daemon, so performInPlace must follow it
        // with an acknowledge (matching the web console's explainAct).
        XCTAssertEqual(stub.acknowledgedFlagIDs, ["f1"])
        XCTAssertEqual(state.inPlaceAction?.phase, .done)
        XCTAssertEqual(stub.fetchFlagsCalls, 1)
        XCTAssertNil(state.heroFlag, "the acknowledged flag must not still demand review after the refetch")
    }

    /// allow-host's mutation can succeed while the follow-up acknowledge
    /// fails (e.g. the daemon restarts between the two requests) — the
    /// finding still needs a look, so the result line must say so and the
    /// button must stay disabled rather than silently reading "Done".
    func testPerformInPlacePartialFailureKeepsButtonDisabled() async {
        let stub = StubDaemonClient()
        let f = FlagModel(id: "f1", rule: "sensitive-read-then-connect", severity: 3, ts: "", pid: 1,
                          agent: "cursor", evidence: [])
        stub.flags = [f]
        stub.acknowledgeError = DaemonClientError.transport("daemon restarting")
        let state = connectedState(stub)
        state.seedFlagsForTesting([f])

        await state.performInPlace(allowHost, on: f)

        XCTAssertEqual(stub.performed, [allowHost])
        XCTAssertTrue(stub.acknowledgedFlagIDs.isEmpty)
        XCTAssertEqual(state.inPlaceAction?.phase,
                       .doneWithWarning("Allowed · dismiss failed: daemon unreachable (daemon restarting)"))
        XCTAssertTrue(state.inPlaceAction?.phase.keepsButtonDisabled ?? false)
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

    /// Table-driven: perform() only trusts an id's exact served method, path
    /// and required body keys — never whatever a malformed or tampered
    /// action happens to carry for that id.
    func testPerformValidatesAgainstServedActionTable() {
        func action(id: String, method: String, path: String, body: [String: JSONValue]?) -> FlagExplainAction {
            FlagExplainAction(id: id, label: "x", consequence: "", method: method, path: path, body: body)
        }

        // dismiss targeting /kill: refused — wrong path for the id.
        XCTAssertThrowsError(try DaemonClient.validate(action(
            id: "dismiss", method: "POST", path: "/kill", body: ["flag_id": .string("f1")])))
        // Right method/path, missing required key: refused.
        XCTAssertThrowsError(try DaemonClient.validate(action(
            id: "allow-host", method: "POST", path: "/allowlist", body: ["agent": .string("cursor")])))
        // An id outside the served table: refused regardless of method/path.
        XCTAssertThrowsError(try DaemonClient.validate(action(
            id: "kill", method: "POST", path: "/kill", body: nil)))

        // Each valid (id, method, path, body) pair: accepted.
        XCTAssertNoThrow(try DaemonClient.validate(action(
            id: "allow-host", method: "POST", path: "/allowlist",
            body: ["agent": .string("cursor"), "host": .string("api.example.com")])))
        XCTAssertNoThrow(try DaemonClient.validate(action(
            id: "allow-path", method: "POST", path: "/guard/path-allow",
            body: ["agent": .string("cursor"), "rule_id": .string("env-files"), "path": .string("/p/.env")])))
        XCTAssertNoThrow(try DaemonClient.validate(action(
            id: "mute-rule-host", method: "POST", path: "/mute",
            body: ["rule": .string("keychain-access"), "host": .string("h")])))
        XCTAssertNoThrow(try DaemonClient.validate(action(
            id: "mute-class", method: "POST", path: "/mute",
            body: ["rule": .string("keychain-access"), "host": .string("*")])))
        XCTAssertNoThrow(try DaemonClient.validate(action(
            id: "dismiss", method: "POST", path: "/flags/acknowledge", body: ["flag_id": .string("f1")])))
        XCTAssertNoThrow(try DaemonClient.validate(action(
            id: "dismiss", method: "POST", path: "/flags/acknowledge", body: ["flag_ids": .array([.string("f1")])])))
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
