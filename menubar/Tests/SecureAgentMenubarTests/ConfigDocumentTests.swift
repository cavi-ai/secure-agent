import XCTest
@testable import SecureAgentMenubar

final class ConfigDocumentTests: XCTestCase {
    // MARK: one test per edit the menu bar makes

    func testDisabledAgentsListReplacedInPlace() throws {
        let yaml = "# daemon config\nfirewall:\n  mode: monitor # keep\n\ndisabled_agents:\n  - cursor # old\n  # note\n  - codex\nother: 1\n"
        let out = try ConfigDocument(yaml).settingList("disabled_agents", to: ["ollama", "lm-studio"]).text
        XCTAssertEqual(out, "# daemon config\nfirewall:\n  mode: monitor # keep\n\ndisabled_agents:\n  - ollama\n  - lm-studio\nother: 1\n")
        XCTAssertEqual(try ConfigDocument(out).list("disabled_agents"), ["ollama", "lm-studio"])
    }

    func testDisabledAgentsListCreatedAfterLeadingComments() throws {
        let yaml = "# daemon config\n\nfirewall:\n  mode: monitor\n"
        let out = try ConfigDocument(yaml).settingList("disabled_agents", to: ["ollama"]).text
        XCTAssertEqual(out, "# daemon config\n\ndisabled_agents:\n  - ollama\nfirewall:\n  mode: monitor\n")
    }

    func testDisabledAgentsRemovedWithItsItems() throws {
        let yaml = "# daemon config\ndisabled_agents:\n  - cursor\n  - codex\nfirewall:\n  mode: monitor\n"
        XCTAssertEqual(try ConfigDocument(yaml).removing("disabled_agents").text, "# daemon config\nfirewall:\n  mode: monitor\n")
        XCTAssertEqual(try ConfigDocument(yaml).removing("missing").text, yaml)
    }

    func testSystemAgentEnabledRewritesOneLine() throws {
        let yaml = "# cfg\nsystem_agent:\n  enabled: false # off\n  model: q\n\nadvisor:\n  enabled: true\n"
        let out = try ConfigDocument(yaml).setting("enabled", to: true, in: "system_agent").text
        XCTAssertEqual(out, "# cfg\nsystem_agent:\n  enabled: true\n  model: q\n\nadvisor:\n  enabled: true\n")
    }

    func testSystemAgentAutoReviewInsertedAtBlockTop() throws {
        let yaml = "system_agent:\n  enabled: true\n\n# tail\nfirewall:\n  mode: monitor\n"
        let out = try ConfigDocument(yaml).setting("auto_review", to: true, in: "system_agent").text
        XCTAssertEqual(out, "system_agent:\n  auto_review: true\n  enabled: true\n\n# tail\nfirewall:\n  mode: monitor\n")
    }

    func testSystemAgentDebugCreatesMissingBlockAtEnd() throws {
        let yaml = "# cfg\nfirewall:\n  mode: monitor\n\n"
        let out = try ConfigDocument(yaml).setting("debug", to: true, in: "system_agent").text
        XCTAssertEqual(out, "# cfg\nfirewall:\n  mode: monitor\n\nsystem_agent:\n  debug: true\n")
    }

    func testAutoReviewScalarAndInlineListKeepTheirForm() throws {
        let yaml = "system_agent:\n  auto_review_min_severity: 2 # cutoff\n  auto_review_excluded_rules: [\"a\"] # types\n  model: q\n\nadvisor:\n  enabled: true\n"
        let out = try ConfigDocument(yaml)
            .setting("auto_review_min_severity", raw: "3", in: "system_agent")
            .settingList("auto_review_excluded_rules", to: ["b", "c"], in: "system_agent").text
        XCTAssertEqual(out, "system_agent:\n  auto_review_min_severity: 3\n  auto_review_excluded_rules: [\"b\", \"c\"]\n  model: q\n\nadvisor:\n  enabled: true\n")
    }

    func testAutoReviewBlockListKeepsItsFormAndEmptiesToInline() throws {
        let yaml = "system_agent:\n  auto_review_excluded_rules:\n  - x\n\n  # note\n  - y\n  model: q\n"
        let document = ConfigDocument(yaml)
        XCTAssertEqual(try document.settingList("auto_review_excluded_rules", to: ["z"], in: "system_agent").text,
                       "system_agent:\n  auto_review_excluded_rules:\n  - z\n  model: q\n")
        XCTAssertEqual(try document.settingList("auto_review_excluded_rules", to: [], in: "system_agent").text,
                       "system_agent:\n  auto_review_excluded_rules: []\n  model: q\n")
    }

    func testAdvisorEnabledRewritesOneLine() throws {
        let yaml = "advisor:\n  enabled: false # off\n  model: \"x\"\nfirewall:\n  mode: monitor\n"
        let out = try ConfigDocument(yaml).setting("enabled", to: true, in: "advisor").text
        XCTAssertEqual(out, "advisor:\n  enabled: true\n  model: \"x\"\nfirewall:\n  mode: monitor\n")
    }

    func testProxyEnabledRewritesTopLevelKeyOnly() throws {
        let yaml = "# cfg\nproxy_enabled: false # keep\nadvisor:\n  # proxy_enabled: no\n  enabled: true\n"
        let out = try ConfigDocument(yaml).setting("proxy_enabled", to: true).text
        XCTAssertEqual(out, "# cfg\nproxy_enabled: true\nadvisor:\n  # proxy_enabled: no\n  enabled: true\n")
    }

    func testProxyEnabledAppendedWithItsComment() throws {
        let yaml = "# cfg\nadvisor:\n  enabled: true"
        let out = try ConfigDocument(yaml).setting("proxy_enabled", to: false, introducedBy: "# proxy\n# second line").text
        XCTAssertEqual(out, "# cfg\nadvisor:\n  enabled: true\n# proxy\n# second line\nproxy_enabled: false\n")
    }

    func testAdvisorModelFieldsSwapManagedForExisting() throws {
        let yaml = "advisor:\n  enabled: true\n  managed: true\n  managed_model: \"m\" # old\n  timeout_ms: 5000\nfirewall:\n  mode: monitor\n"
        let out = try ConfigDocument(yaml)
            .removing("managed", in: "advisor").removing("managed_model", in: "advisor")
            .setting("endpoint", raw: ConfigDocument.quoted("http://127.0.0.1:11434"), in: "advisor")
            .setting("model", raw: ConfigDocument.quoted("qwen3:4b"), in: "advisor").text
        XCTAssertEqual(out, "advisor:\n  model: \"qwen3:4b\"\n  endpoint: \"http://127.0.0.1:11434\"\n  enabled: true\n  timeout_ms: 5000\nfirewall:\n  mode: monitor\n")
    }

    func testAdvisorRuntimeFieldsRewriteTheirLines() throws {
        let yaml = "advisor:\n  enabled: true\n  timeout_ms: 60000 # cold\n  classifier_endpoint: # off\n  classifier_model: 'kev-latest' # mine\n  debug: false\nfirewall:\n  mode: monitor\n"
        let prefs = AdvisorPreferences(timeoutMS: 90000, classifierEndpoint: "http://127.0.0.1:8009", classifierModel: "kev-2", debug: true)
        XCTAssertEqual(try prefs.updating(yaml),
                       "advisor:\n  enabled: true\n  timeout_ms: 90000\n  classifier_endpoint: \"http://127.0.0.1:8009\"\n  classifier_model: \"kev-2\"\n  debug: true\nfirewall:\n  mode: monitor\n")
    }

    // MARK: refusals

    func testAmbiguousDocumentsAreRefusedForEveryField() {
        let documents = [
            "flow style": "advisor: {enabled: true}\n",
            "flow document": "{advisor: {enabled: true}}\n",
            "document start": "---\nadvisor:\n  enabled: true\n",
            "document end": "advisor:\n  enabled: true\n...\n",
            "duplicate header": "advisor:\nadvisor:\n",
            "quoted header": "'advisor':\n  enabled: true\n",
            "spaced header": "advisor :\n  enabled: true\n",
            "value on header": "advisor: yes\n  enabled: true\n",
            "tab in block": "advisor:\n  enabled: true\n\t\n",
        ]
        for (name, yaml) in documents {
            let document = ConfigDocument(yaml)
            XCTAssertThrowsError(try document.scalar("enabled", in: "advisor"), name)
            XCTAssertThrowsError(try document.setting("enabled", to: true, in: "advisor"), name)
            XCTAssertThrowsError(try document.settingList("rules", to: ["a"], in: "advisor"), name)
            XCTAssertThrowsError(try document.removing("enabled", in: "advisor"), name)
        }
    }

    func testDuplicateKeysAndNestedValuesAreRefusedForTheKeyInvolved() {
        for yaml in ["advisor:\n  enabled: true\n  enabled: false\n", "advisor:\n  enabled:\n    nested: true\n"] {
            let document = ConfigDocument(yaml)
            XCTAssertThrowsError(try document.scalar("enabled", in: "advisor"), yaml)
            XCTAssertThrowsError(try document.setting("enabled", to: true, in: "advisor"), yaml)
        }
    }

    func testTopLevelKeysFollowTheSameRules() {
        for yaml in ["proxy_enabled: true\nproxy_enabled: false\n", "'proxy_enabled': true\n", "proxy_enabled :  true\n",
                     "---\nproxy_enabled: true\n", "proxy_enabled:\n  nested: true\n", "proxy_enabled: true\n\t- x\n"] {
            XCTAssertThrowsError(try ConfigDocument(yaml).setting("proxy_enabled", to: false), yaml)
        }
    }

    func testUnreadableValuesAreRefused() {
        for value in ["[a]", "{a: 1}", "|", "*alias", "\"unterminated", "'bad' tail", "\"x\" tail"] {
            XCTAssertThrowsError(try ConfigDocument("advisor:\n  model: \(value)\n").scalar("model", in: "advisor"), value)
        }
        XCTAssertThrowsError(try ConfigDocument("advisor:\n  rules: plain\n").list("rules", in: "advisor"))
        XCTAssertThrowsError(try ConfigDocument("advisor:\n  rules:\n    key: value\n").list("rules", in: "advisor"))
        XCTAssertThrowsError(try ConfigDocument("advisor:\n  rules:\n    key: value\n").removing("rules", in: "advisor"))
    }

    // MARK: reading

    func testScalarsAreReadUnquoted() throws {
        let yaml = "advisor:\n  a: \"x # y\" # c\n  b: 'it''s'\n  c: plain # c\n  d: # off\n  e:\n"
        let document = ConfigDocument(yaml)
        XCTAssertEqual(try document.scalar("a", in: "advisor"), .init(text: "x # y", isQuoted: true))
        XCTAssertEqual(try document.scalar("b", in: "advisor"), .init(text: "it's", isQuoted: true))
        XCTAssertEqual(try document.scalar("c", in: "advisor"), .init(text: "plain", isQuoted: false))
        XCTAssertEqual(try document.scalar("d", in: "advisor")?.text, "")
        XCTAssertEqual(try document.scalar("e", in: "advisor")?.text, "")
        XCTAssertNil(try document.scalar("missing", in: "advisor"))
        XCTAssertNil(try document.scalar("a", in: "other"))
    }

    func testFlagAndBlockQueries() throws {
        let document = ConfigDocument("firewall:\n  enabled: true\nadvisor:\n  enabled: true # on\n  debug: maybe\n")
        XCTAssertTrue(document.flag("enabled", in: "advisor"))
        XCTAssertFalse(document.flag("debug", in: "advisor"))
        XCTAssertFalse(document.flag("enabled", in: "system_agent"))
        XCTAssertTrue(try document.hasBlock("advisor"))
        XCTAssertFalse(try document.hasBlock("system_agent"))
    }

    func testInlineListRoundTrip() throws {
        let document = try ConfigDocument("system_agent:\n  rules: [a, \"b\"] # types\n").settingList("rules", to: ["c", "d e"], in: "system_agent")
        XCTAssertEqual(document.text, "system_agent:\n  rules: [\"c\", \"d e\"]\n")
        XCTAssertEqual(try document.list("rules", in: "system_agent"), ["c", "d e"])
        XCTAssertEqual(try ConfigDocument("system_agent:\n  rules: []\n").list("rules", in: "system_agent"), [])
    }

    func testBlockListRoundTrip() throws {
        let document = try ConfigDocument("system_agent:\n  rules:\n    - a\n  model: q\n").settingList("rules", to: ["c", "true", "d e"], in: "system_agent")
        XCTAssertEqual(document.text, "system_agent:\n  rules:\n    - c\n    - \"true\"\n    - \"d e\"\n  model: q\n")
        XCTAssertEqual(try document.list("rules", in: "system_agent"), ["c", "true", "d e"])
        let created = try ConfigDocument("system_agent:\n  model: q\n").settingList("rules", to: ["a", "b"], in: "system_agent")
        XCTAssertEqual(created.text, "system_agent:\n  rules:\n    - a\n    - b\n  model: q\n")
        XCTAssertEqual(try created.list("rules", in: "system_agent"), ["a", "b"])
    }

    func testIndentedBlocksKeepTheirIndentation() throws {
        let out = try ConfigDocument("advisor:\n    enabled: false\n").setting("debug", to: true, in: "advisor").text
        XCTAssertEqual(out, "advisor:\n    debug: true\n    enabled: false\n")
    }

    // MARK: disk

    func testStoreCreatesMissingFileAndRefusesWithoutWriting() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("config-store-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let store = ConfigStore(home: directory)
        XCTAssertEqual(try store.document().text, "")
        try store.update { try ConfigDocument($0).setting("enabled", to: true, in: "advisor").text }
        XCTAssertEqual(try String(contentsOfFile: store.path, encoding: .utf8), "advisor:\n  enabled: true\n")

        try "advisor: {enabled: true}\n".write(toFile: store.path, atomically: true, encoding: .utf8)
        XCTAssertThrowsError(try store.update { try ConfigDocument($0).setting("enabled", to: false, in: "advisor").text })
        XCTAssertEqual(try String(contentsOfFile: store.path, encoding: .utf8), "advisor: {enabled: true}\n")
    }
}
