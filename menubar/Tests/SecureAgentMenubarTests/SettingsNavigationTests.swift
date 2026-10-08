import AppKit
import XCTest
@testable import SecureAgentMenubar

final class SettingsNavigationTests: XCTestCase {
    func testEverySidebarSymbolExists() {
        for tab in SettingsTab.allCases {
            XCTAssertNotNil(NSImage(systemSymbolName: tab.symbol, accessibilityDescription: tab.title), tab.title)
        }
    }

    @MainActor
    func testEveryRowSymbolExists() {
        let symbols = SettingsView.guardRules.map(\.symbol) + SettingsView.notifyRules.map(\.symbol)
            + ["eye", "lock.shield.fill", "checkmark.shield.fill", "shield.lefthalf.filled",
               "bell.badge.fill", "network.slash", "eye.slash", "doc"]
        for symbol in symbols {
            XCTAssertNotNil(NSImage(systemSymbolName: symbol, accessibilityDescription: nil), symbol)
        }
    }

    func testEveryTabSitsInExactlyOneSidebarSection() {
        XCTAssertEqual(SettingsSection.allCases.flatMap(\.tabs), SettingsTab.allCases)
    }

    /// "Settings → Secure Agent → Chat|Traffic" in the README, the daemon's
    /// Doctor fixes and the web console stay true paths.
    func testSecureAgentSectionHoldsChatAnalysisTraffic() {
        XCTAssertEqual(SettingsSection.secureAgent.rawValue, "Secure Agent")
        XCTAssertEqual(SettingsSection.secureAgent.tabs, [.chat, .analysis, .traffic])
        XCTAssertEqual(SettingsTab.chat.title, "Chat")
        XCTAssertEqual(SettingsTab.traffic.title, "Traffic")
    }

    private func defaultsYAML() throws -> String {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent("daemon/internal/config/defaults.yaml"), encoding: .utf8)
    }

    /// Providers lists every harness the daemon ships, with the daemon's own
    /// match strings.
    @MainActor
    func testProvidersMatchDaemonDefaultAgents() throws {
        var inAgents = false
        var shipped: [(name: String, matches: [String])] = []
        for line in try defaultsYAML().split(separator: "\n", omittingEmptySubsequences: false) {
            if line.hasPrefix("agents:") { inAgents = true; continue }
            if inAgents, let first = line.first, first != " ", first != "#" { break }
            guard inAgents, let name = line.range(of: "name: "), let match = line.range(of: "match: [") else { continue }
            let agent = line[name.upperBound...].prefix { $0 != "," }.trimmingCharacters(in: .whitespaces)
            let list = line[match.upperBound...].prefix { $0 != "]" }
                .split(separator: ",").map { $0.trimmingCharacters(in: CharacterSet(charactersIn: " \"")) }
            shipped.append((agent, list))
        }
        let hosts: Set<String> = ["claude-desktop", "cursor-ide"]
        let expected = shipped.filter { !hosts.contains($0.name) }
        XCTAssertGreaterThanOrEqual(expected.count, 15, "defaults.yaml agents list not found")
        XCTAssertEqual(SetupManager.knownAgents.map(\.name), expected.map(\.name))
        for (known, daemon) in zip(SetupManager.knownAgents, expected) {
            XCTAssertEqual(known.matches, daemon.matches, known.name)
        }
    }

    /// Harnesses without a drawn mark show their monogram, never an empty tile.
    @MainActor
    func testEveryProviderTileDrawsAMarkOrMonogram() {
        XCTAssertEqual(AgentIdentity.glyph(for: "claude"), .claude)
        XCTAssertEqual(AgentIdentity.glyph(for: "lm-studio"), .lmStudio)
        for name in ["pi", "qwen-code", "windsurf", "aider", "codeium", "copilot", "openclaw", "hermes", "unlisted"] {
            XCTAssertEqual(AgentIdentity.glyph(for: name), .monogram, name)
            XCTAssertFalse(AgentIdentity.forAgent(name).monogram.isEmpty, name)
        }
        XCTAssertTrue(AgentIdentity.forAgent("openclaw").known)
        XCTAssertTrue(AgentIdentity.forAgent("hermes").known)
    }

    /// Every pattern shipped in defaults.yaml has a display title, so a new
    /// default rule cannot reach Settings as a bare id unnoticed.
    func testFirewallTitlesCoverEveryDefaultPattern() throws {
        let yaml = try defaultsYAML()
        let ids = yaml.split(separator: "\n").compactMap { line -> String? in
            guard let open = line.range(of: "- { id: ") else { return nil }
            return line[open.upperBound...].split(separator: ",").first.map {
                $0.trimmingCharacters(in: .whitespaces)
            }
        }
        XCTAssertGreaterThanOrEqual(ids.count, 20, "defaults.yaml pattern list not found")
        for id in ids {
            XCTAssertNotNil(FirewallRuleCatalog.titles[id], "no Settings title for default firewall rule \(id)")
        }
    }

    func testFirewallGroupsFollowTypeOrderAndKeepUnknownTypes() {
        let rows = [("z-custom", "custom-type"), ("aws-key", "cloud-key"), ("entropy", "unknown"),
                    ("anthropic-key", "vendor-key"), ("untyped", nil), ("private-key", "private-key")]
            .map { AppState.FirewallRuleRow(id: $0.0, stat: RuleStatModel(type: $0.1)) }
        let groups = FirewallRuleCatalog.groups(rows)
        XCTAssertEqual(groups.map(\.id), ["vendor-key", "cloud-key", "private-key", "unknown", "other"])
        XCTAssertEqual(groups.first { $0.id == "unknown" }?.rules.map(\.id), ["entropy", "untyped"])
        XCTAssertEqual(groups.last?.rules.map(\.id), ["z-custom"])
    }

    func testFirewallGroupSortsByTitle() {
        let rows = ["github-pat", "anthropic-key", "bearer-token"]
            .map { AppState.FirewallRuleRow(id: $0, stat: RuleStatModel(type: "vendor-key")) }
        XCTAssertEqual(FirewallRuleCatalog.groups(rows).first?.rules.map(\.id),
                       ["anthropic-key", "bearer-token", "github-pat"])
    }

    @MainActor
    func testMutesGroupOncePerRuleInOrder() {
        let mutes: [SettingsView.Mute] = [
            ("keychain-access", "*", nil, "Agent touched the keychain"),
            ("sensitive-read-then-connect", "10.0.0.1", "claude", "Sensitive file read"),
            ("sensitive-read-then-connect", "example.com", nil, nil),
        ]
        let groups = SettingsView.muteGroups(mutes)
        XCTAssertEqual(groups.map(\.rule), ["keychain-access", "sensitive-read-then-connect"])
        XCTAssertEqual(groups.map(\.title), ["Agent touched the keychain", "Sensitive file read"])
        XCTAssertEqual(groups.last?.rows.map(\.host), ["10.0.0.1", "example.com"])
    }

    func testBulkActionBlocksOnlyMonitoringRulesThenOffersMonitorAll() {
        func group(_ id: String, _ modes: [(String, String?)]) -> FirewallRuleCatalog.Group {
            FirewallRuleCatalog.Group(id: id, title: id, rules: modes.map {
                AppState.FirewallRuleRow(id: $0.0, stat: RuleStatModel(mode: $0.1, type: id))
            })
        }
        XCTAssertEqual(FirewallRuleCatalog.bulkAction(for: group("vendor-key", [("a", "block"), ("b", "monitor"), ("c", nil)])),
                       .init(title: "Block all", mode: "block", rules: ["b", "c"]))
        XCTAssertEqual(FirewallRuleCatalog.bulkAction(for: group("cloud-key", [("a", "block"), ("b", "block")])),
                       .init(title: "Monitor all", mode: "monitor", rules: ["a", "b"]))
        XCTAssertNil(FirewallRuleCatalog.bulkAction(for: group("unknown", [("entropy", "monitor")])))
    }

    func testFirewallTitleFallsBackToID() {
        XCTAssertEqual(FirewallRuleCatalog.title(for: "anthropic-key"), "Anthropic API key")
        XCTAssertEqual(FirewallRuleCatalog.title(for: "fp-7c1e9a"), "fp-7c1e9a")
    }

    @MainActor
    func testRowSubtitlesNameWhatEachChoiceDoes() {
        XCTAssertEqual(SettingsView.guardModeEffect("monitor"), "Logged, never interrupted")
        XCTAssertEqual(SettingsView.guardModeEffect("prompt"), "Asks you before the agent proceeds")
        XCTAssertEqual(SettingsView.guardModeEffect("deny"), "Blocked outright")
        XCTAssertEqual(SettingsView.notifyEffect("default"), "Notifies when the flag is critical")
        XCTAssertEqual(SettingsView.notifyEffect("always"), "Notifies on every flag of this type")
        XCTAssertEqual(SettingsView.notifyEffect("never"), "Silent; still listed in the menu bar and console")
    }
}
