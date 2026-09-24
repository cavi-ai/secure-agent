import XCTest
@testable import SecureAgentMenubar

/// The popover hero reads the daemon's verdict: state from /posture, the top
/// unacted flag by served disposition, and its recommended action.
@MainActor
final class HeroModelTests: XCTestCase {

    private func state(flags: [FlagModel]) -> AppState {
        AppState.previewFlags(flags)
    }

    private func flag(id: String, sev: Int, acked: Bool) -> FlagModel {
        FlagModel(id: id, rule: "keychain-access", severity: sev, ts: "",
                  pid: 901, agent: "cursor", evidence: [], acknowledged: acked)
    }

    private func served(_ id: String, sev: Int = 3, disposition: String, text: String,
                        rec: String? = nil, acked: Bool = false) -> FlagModel {
        let actions = ["allow-host", "dismiss"].map {
            FlagExplainAction(id: $0, label: $0 == "allow-host" ? "Allow api.example.com for cursor" : "Dismiss",
                              consequence: "c-\($0)", method: "POST", path: $0 == "allow-host" ? "/allowlist" : "/flags/acknowledge",
                              body: ["agent": .string("cursor")], recommended: $0 == rec ? true : nil)
        }
        return FlagModel(id: id, rule: "sensitive-read-then-connect", severity: sev, ts: "", pid: 901, agent: "cursor",
                         evidence: [], acknowledged: acked, title: "Agent read a secret, then connected out",
                         explain: FlagExplain(what: "Cursor read a sensitive file, then reached api.example.com.",
                                              disposition: FlagDisposition(state: disposition, text: text, why: ""),
                                              actions: actions))
    }

    private func posture(_ state: String, _ summary: String) -> PostureModel {
        PostureModel(state: state, needsYou: state == "all-clear" ? 0 : 1, summary: summary, connected: true)
    }

    func testReviewedFlagsDoNotDemandReview() {
        // 20 sev-2 flags, ALL acknowledged → no flag in the hero.
        let s = state(flags: (1...20).map { flag(id: "f\($0)", sev: 2, acked: true) })
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Protected")
        XCTAssertNil(hero.flag)
        XCTAssertNil(hero.action)
    }

    /// The reported lie: a 93 %-benign severity-3 flag read "Action needed"
    /// while /posture and the console said attention.
    func testBenignLikelyCriticalSeverityFollowsPosture() {
        let s = state(flags: [served("b1", disposition: "benign-likely", text: "Likely benign (advisor 93 %)", rec: "allow-host")])
        s.seedPostureForTesting(posture("attention", "1 item needs you — first: Finding, likely benign."))
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertNotEqual(hero.title, "Action needed")
        XCTAssertEqual(hero.title, "Needs a look")
        XCTAssertEqual(hero.color, .warn)
        XCTAssertEqual(hero.subtitle, "1 item needs you — first: Finding, likely benign.")
        XCTAssertEqual(hero.flag?.id, "b1")
        XCTAssertEqual(hero.flagLines, ["Agent read a secret, then connected out",
                                        "Cursor read a sensitive file, then reached api.example.com.",
                                        "Likely benign (advisor 93 %)"])
        XCTAssertEqual(hero.buttonLabel, "Allow api.example.com for cursor")
        guard case .perform(let a) = hero.action else {
            XCTFail("recommended allow-host must run in place")
            return
        }
        XCTAssertEqual(a.id, "allow-host")
        XCTAssertEqual(ConsoleView.actionHelp(hero.action!), "c-allow-host")
    }

    func testPostureCriticalStylesCritical() {
        let s = state(flags: [served("c1", disposition: "critical", text: "Act now")])
        s.seedPostureForTesting(posture("critical", "Agent read a secret, then connected out — act now."))
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Action needed")
        XCTAssertEqual(hero.color, .bad)
        XCTAssertEqual(hero.icon, "exclamationmark.shield.fill")
        XCTAssertEqual(hero.subtitle, "Agent read a secret, then connected out — act now.")
        XCTAssertEqual(hero.buttonLabel, "Open in console")
    }

    func testPostureAllClearIsProtected() {
        let s = state(flags: [])
        s.seedPostureForTesting(posture("all-clear", "All clear — agents monitored, no action needed."))
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Protected")
        XCTAssertEqual(hero.color, .ok)
        XCTAssertEqual(hero.subtitle, "All clear — agents monitored, no action needed.")
    }

    /// critical > warning > benign-likely, whatever the list order.
    func testTopFlagByDispositionPrecedence() {
        let s = state(flags: [served("b", disposition: "benign-likely", text: "Likely benign (advisor 90 %)"),
                              served("w", disposition: "warning", text: "Needs a look"),
                              served("c", sev: 2, disposition: "critical", text: "Act now"),
                              served("a", disposition: "acknowledged", text: "Reviewed", acked: true)])
        XCTAssertEqual(s.heroFlag?.id, "c")
        let noCritical = state(flags: [served("b", disposition: "benign-likely", text: "x"),
                                       served("w", disposition: "warning", text: "y")])
        XCTAssertEqual(noCritical.heroFlag?.id, "w")
    }

    func testPickerAllowHostPerforms() {
        guard case .perform(let a) = AppState.heroAction(for: served("f", disposition: "benign-likely", text: "x", rec: "allow-host")) else {
            XCTFail("allow-host must perform")
            return
        }
        XCTAssertEqual(a.id, "allow-host")
        XCTAssertEqual(a.path, "/allowlist")
    }

    func testPickerKillOpensConsole() {
        let kill = FlagExplainAction(id: "kill", label: "Stop cursor", consequence: "", method: "POST",
                                     path: "/kill", body: ["pid": .int(901)], recommended: true)
        let f = FlagModel(id: "k", rule: "proxy-secret-leak", severity: 3, ts: "", pid: 901, agent: "cursor", evidence: [],
                          explain: FlagExplain(what: "w", disposition: FlagDisposition(state: "critical", text: "Act now", why: ""),
                                               actions: [kill]))
        XCTAssertEqual(AppState.heroAction(for: f), .openConsole(tab: "findings"))
    }

    func testPickerNoRecommendationOpensConsole() {
        XCTAssertEqual(AppState.heroAction(for: served("n", disposition: "warning", text: "Needs a look")),
                       .openConsole(tab: "findings"))
        XCTAssertEqual(AppState.heroAction(for: flag(id: "old", sev: 3, acked: false)), .openConsole(tab: "findings"))
    }

    func testUnactedFlagWithoutPostureNeedsALook() {
        let s = state(flags: [flag(id: "f1", sev: 2, acked: false), flag(id: "f2", sev: 2, acked: true)])
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Needs a look")
        XCTAssertEqual(hero.flag?.id, "f1")
    }

    func testCriticalUnactedWithoutPostureStillEscalates() {
        let s = state(flags: [flag(id: "f1", sev: 3, acked: false)])
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Action needed")
        XCTAssertEqual(hero.buttonLabel, "Open in console")
    }

    // MARK: status-icon sync

    private func incident(_ id: String, status: String) -> IncidentReportModel {
        IncidentReportModel(id: id, flagId: "flag-\(id)", pid: 901, agent: "cursor",
                            timestamp: "", rule: "proxy-secret-leak", summary: "s",
                            risk: "CRITICAL", touchedFiles: [], connections: [],
                            rotateList: [], workflow: IncidentWorkflowModel(status: status))
    }

    /// Regression: the menu-bar status icon keyed on raw flags/incidents, so an
    /// acknowledged flag or resolved incident kept the warning lit forever —
    /// "the menu bar warning is always there no matter what". It must read the
    /// same predicate as the hero and console.
    func testNeedsAttentionIgnoresAcknowledgedAndResolved() {
        let acked = AppState.previewFlagsAndIncidents([flag(id: "f1", sev: 3, acked: true)], [])
        XCTAssertFalse(acked.needsAttention, "an acknowledged critical must clear the warning")

        let resolved = AppState.previewFlagsAndIncidents([], [incident("i1", status: "resolved")])
        XCTAssertFalse(resolved.needsAttention, "a resolved incident must clear the warning")

        let open = AppState.previewFlagsAndIncidents([], [incident("i2", status: "open")])
        XCTAssertTrue(open.needsAttention, "an open incident must keep the warning")

        let liveCritical = AppState.previewFlagsAndIncidents([flag(id: "f2", sev: 3, acked: false)], [])
        XCTAssertTrue(liveCritical.needsAttention, "an unacted critical must keep the warning")
    }

    /// Acknowledged criticals must not resurface in the hero either — the hero
    /// and the status icon share the unactedCriticals predicate.
    func testAcknowledgedCriticalDoesNotEscalateHero() {
        let s = state(flags: [flag(id: "f1", sev: 3, acked: true)])
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Protected", "acked critical must not say Action needed")
    }

    func testResolvedIncidentDoesNotEscalateHero() {
        let s = AppState.previewFlagsAndIncidents([], [incident("i1", status: "resolved")])
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Protected", "resolved incident must not say Action needed")
    }
}
