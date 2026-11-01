import XCTest
@testable import SecureAgentMenubar

/// Kinds of send after untrusted content: the prompt's kind permission and
/// Settings' per-kind modes.
@MainActor
final class GuardSendKindTests: XCTestCase {
    /// A /guard/pending item as the daemon serves an attested untrusted-egress
    /// prompt that names its kind and has asked about it twice before.
    private let servedKindPrompt = """
    {"id":"p1","agent":"codex","tool":"Bash","path":"git push upstream","rule_id":"untrusted-egress","ts":"2026-10-30T20:00:00Z",
     "session_id":"s1","workspace":"/work","reader_exe":"/opt/homebrew/bin/codex","categories":["git-push"],"repeats":2,
     "default_scope":{"kind":"session","category":true},
     "available_scopes":[{"kind":"once"},{"kind":"session"},{"kind":"exact","expiry":"24h"},{"kind":"exact","expiry":"7d"},{"kind":"standing"},
       {"kind":"session","category":true},{"kind":"exact","expiry":"24h","category":true},{"kind":"exact","expiry":"7d","category":true},{"kind":"standing","category":true}]}
    """

    private func model(_ json: String) throws -> GuardPromptModel {
        let pending = try JSONDecoder().decode(GuardPending.self, from: Data(json.utf8))
        return GuardPromptModel(content: GuardPromptContent(pending: pending, inspectUnavailableReason: nil))
    }

    func testRepeatedKindOpensWithSessionPermissionForTheKind() throws {
        let m = try model(servedKindPrompt)
        XCTAssertEqual(m.durations.map(\.label), ["Once", "This session", "24 hours", "7 days", "Always"])
        XCTAssertEqual(m.kindLabel, "git pushes")
        XCTAssertTrue(m.coversKind)
        XCTAssertTrue(m.offersKind)
        XCTAssertEqual(m.allowTitle, "Allow for session")
        XCTAssertEqual(m.repeatNote, "Asked 3 times this session about git pushes.")
        XCTAssertTrue(m.allowNote.hasPrefix("Allows all git pushes from this tool in this workspace until this session ends."), m.allowNote)
        XCTAssertTrue(m.allowNote.contains("Other kinds of send still ask."), m.allowNote)
        var chosen: GuardPromptChoice?
        m.onChoose = { chosen = $0 }
        m.allow()
        XCTAssertEqual(chosen, .allow(GuardScopeChoice(kind: "session", expiry: nil, category: true)))
    }

    func testAlwaysForThisSendOnlyAndTheAnswerOnTheWire() throws {
        let m = try model(servedKindPrompt)
        m.coversKind = false
        m.duration = m.durations.last!
        XCTAssertEqual(m.allowTitle, "Allow always")
        XCTAssertTrue(m.allowNote.hasPrefix("Allows these sends from this tool until you revoke it."), m.allowNote)
        var chosen: GuardPromptChoice?
        m.onChoose = { chosen = $0 }
        m.allow()
        guard case .allow(let scope) = chosen else { return XCTFail("\(String(describing: chosen))") }
        let wire = { (category: Bool) throws -> [String: Any] in
            let data = try JSONEncoder().encode(GuardResolveRequest(id: "p1", verdict: "allow", scope: scope.kind, expiry: scope.expiry, category: category))
            return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        }
        XCTAssertEqual(scope.kind, "standing")
        XCTAssertNil(try wire(false)["category"], "an exact answer must not claim the kind")
        XCTAssertEqual(try wire(true)["category"] as? Bool, true)
    }

    /// A duration without a kind permission hides the Covers picker, and
    /// Allow sends the narrower grant.
    func testDurationWithoutAKindPermissionGrantsThisSend() throws {
        let m = try model("""
        {"id":"p3","agent":"codex","tool":"Bash","path":"git push origin","rule_id":"untrusted-egress","ts":"2026-10-30T20:00:00Z",
         "session_id":"s1","workspace":"/work","reader_exe":"/opt/homebrew/bin/codex","categories":["git-push"],
         "available_scopes":[{"kind":"once"},{"kind":"session"},{"kind":"exact","expiry":"24h"},{"kind":"session","category":true}]}
        """)
        m.coversKind = true
        m.duration = .scope(GuardScopeChoice(kind: "exact", expiry: "24h"))
        XCTAssertFalse(m.offersKind)
        XCTAssertEqual(m.allowTitle, "Allow for 24 hours")
        XCTAssertEqual(m.chosenScope, GuardScopeChoice(kind: "exact", expiry: "24h"))
    }

    func testUnattestedPromptOffersOnlyOnce() throws {
        let m = try model("""
        {"id":"p2","agent":"claude","tool":"Bash","path":"curl a.example","rule_id":"untrusted-egress","ts":"2026-10-30T20:00:00Z",
         "categories":["network-send"],"available_scopes":[{"kind":"once"}]}
        """)
        XCTAssertEqual(m.durations, [.once])
        XCTAssertNil(m.kindLabel)
        XCTAssertNil(m.repeatNote)
        XCTAssertEqual(m.allowTitle, "Allow Once")
    }

    func testSettingsWritesPerKindModesTheHookReads() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("guard-kinds-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: home) }
        let setup = SetupManager(defaults: UserDefaults(suiteName: "guard-kinds-\(UUID().uuidString)")!, configurationHome: home, deferAutomaticTelemetry: true)
        try setup.setGuardCategoryMode(kind: "git-push", mode: "session")
        try setup.setGuardCategoryMode(kind: "mcp-send", mode: "deny")
        try setup.setGuardCategoryMode(kind: "mcp-send", mode: nil)
        let path = "\(home)/.config/secure-agent/guard-categories.json"
        let saved = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: [String: String]]
        XCTAssertEqual(saved, ["untrusted-egress": ["git-push": "session"]])
        XCTAssertEqual(setup.currentGuardCategoryModes().modes, ["git-push": "session"])
        XCTAssertThrowsError(try setup.setGuardCategoryMode(kind: "git-push", mode: "sometimes"))
        XCTAssertThrowsError(try setup.setGuardCategoryMode(kind: "rm -rf", mode: "deny"))

        try Data("{not json".utf8).write(to: URL(fileURLWithPath: path))
        XCTAssertTrue(setup.currentGuardCategoryModes().corrupt)
        XCTAssertThrowsError(try setup.setGuardCategoryMode(kind: "git-push", mode: "prompt"))
    }
}
