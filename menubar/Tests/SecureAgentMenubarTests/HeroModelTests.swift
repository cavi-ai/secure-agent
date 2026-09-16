import XCTest
@testable import SecureAgentMenubar

/// Regression: the popover hero counted EVERY severity≥2 flag in the fetch
/// window — including ones the operator had already reviewed/dismissed — so
/// it read "20 flags to review" over a list where all 20 were long handled.
/// The hero must use the same unacted filter as the attention section:
/// acknowledged flags never demand attention again.
@MainActor
final class HeroModelTests: XCTestCase {

    private func state(flags: [FlagModel], uninspected: Int = 0, wouldBlock: Int = 0) -> AppState {
        AppState.previewFlags(flags, uninspected: uninspected, wouldBlock: wouldBlock)
    }

    private func flag(id: String, sev: Int, acked: Bool) -> FlagModel {
        FlagModel(id: id, rule: "keychain-access", severity: sev, ts: "",
                  pid: 901, agent: "cursor", evidence: [], acknowledged: acked)
    }

    func testReviewedFlagsDoNotDemandReview() {
        // The screenshot case: 20 sev-2 flags, ALL acknowledged → no
        // "N flags to review" in the hero.
        let s = state(flags: (1...20).map { flag(id: "f\($0)", sev: 2, acked: true) })
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Protected")
        XCTAssertFalse(hero.subtitle.contains("to review"), "hero lied: \(hero.subtitle)")
        XCTAssertNil(hero.action)
    }

    func testUnactedWarningFlagCounts() {
        let s = state(flags: [flag(id: "f1", sev: 2, acked: false),
                              flag(id: "f2", sev: 2, acked: true)])
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Attention")
        XCTAssertTrue(hero.subtitle.contains("1 flag to review"), "hero: \(hero.subtitle)")
        // "N flags to review" must be clickable — the top unacted flag's sheet.
        guard case .flag = hero.action else {
            XCTFail("flags-to-review hero must open the top flag's action sheet")
            return
        }
    }

    func testUninspectedAloneStillEarnsAttention() {
        // Zero unacted flags but a real blind spot — Attention stays, and the
        // subtitle names only the true item. And it is CLICKABLE: the egress
        // drill-down in the console ("if I can't click it I don't wanna see it").
        let s = state(flags: [flag(id: "f1", sev: 2, acked: true)], uninspected: 34)
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Attention")
        XCTAssertEqual(hero.subtitle, "34 uninspected")
        guard case .openConsole(let tab) = hero.action else {
            XCTFail("uninspected hero must open the console egress tab")
            return
        }
        XCTAssertEqual(tab, "egress")
    }

    func testCriticalUnactedStillEscalates() {
        let s = state(flags: [flag(id: "f1", sev: 3, acked: false)])
        let hero = ConsoleView(state: s, scrollable: false).heroModel
        XCTAssertEqual(hero.title, "Action needed")
        guard case .flag = hero.action else {
            XCTFail("critical hero must open the flag's action sheet")
            return
        }
    }
}
