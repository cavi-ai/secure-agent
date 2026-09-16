import XCTest
@testable import SecureAgentMenubar

/// The session board must group by harness family — the flat 50-row list was
/// unreadable with a busy fleet. Families are ordered by their best row in
/// the active sort; sessions stay sorted within each family.
@MainActor
final class SessionFamilyTests: XCTestCase {

    private func agent(_ pid: Int32, _ name: String, rss: UInt64 = 0, seen: String = "") -> AgentSummaryModel {
        AgentSummaryModel(pid: pid, name: name, cwd: "/tmp/\(name)-\(pid)",
                          lastSeenAt: seen, rssBytes: rss)
    }

    func testFamiliesGroupByHarnessInSortOrder() {
        let s = AppState.previewAgents([
            agent(1, "cursor", rss: 100, seen: "2026-09-15T10:00:00Z"),
            agent(2, "codex", rss: 900, seen: "2026-09-15T12:00:00Z"),
            agent(3, "cursor", rss: 50, seen: "2026-09-15T11:00:00Z"),
            agent(4, "claude", rss: 10, seen: "2026-09-15T09:00:00Z"),
        ])

        // lastActivity: codex (12:00) family first, then cursor (11:00 best), then claude.
        let fams = s.sessionBoardFamilies(sortedBy: .lastActivity)
        XCTAssertEqual(fams.map(\.name), ["codex", "cursor", "claude"])
        XCTAssertEqual(fams[1].rows.map(\.agent.pid), [3, 1]) // cursor sessions newest-first within family
        XCTAssertEqual(fams[1].rows.count, 2)

        // memory: cursor family (150 total) still below codex (900) → codex first.
        let byMem = s.sessionBoardFamilies(sortedBy: .memory)
        XCTAssertEqual(byMem.map(\.name), ["codex", "cursor", "claude"])
        XCTAssertEqual(byMem[1].totalRSSBytes, 150)
    }

    func testFamilyAggregates() {
        let s = AppState.previewAgents([
            agent(1, "cursor", rss: 100, seen: "2026-09-15T10:00:00Z"),
            agent(2, "cursor", rss: 40, seen: "2026-09-15T12:00:00Z"),
        ])
        let fam = s.sessionBoardFamilies(sortedBy: .lastActivity)[0]
        XCTAssertEqual(fam.totalRSSBytes, 140)
        XCTAssertEqual(fam.lastSeenAt, "2026-09-15T12:00:00Z")
    }

    func testSingleAgentFormsOwnFamily() {
        let s = AppState.previewAgents([agent(1, "codex")])
        let fams = s.sessionBoardFamilies(sortedBy: .lastActivity)
        XCTAssertEqual(fams.count, 1)
        XCTAssertEqual(fams[0].rows.count, 1)
    }
}
