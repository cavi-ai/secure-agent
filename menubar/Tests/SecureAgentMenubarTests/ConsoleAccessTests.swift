import XCTest
@testable import SecureAgentMenubar

/// Regression coverage for the console-access fixes:
///  1. "Open console" was a greyed-out dead end when the inspection proxy was
///     off — the one-click enable writes proxy_enabled into config.yaml
///     WITHOUT clobbering the user's other keys (a full-file rewrite is how
///     the proxy setting was lost in the first place).
///  2. Every click used to open a duplicate console tab that dead-ended —
///     the focus-or-open scripts target an existing tab instead.
final class ConsoleAccessTests: XCTestCase {

    // MARK: proxy_enabled writer

    func testProxyEnableReplacesTopLevelKeyOnly() {
        let yaml = """
        # user config
        net_sample_interval_ms: 2000
        proxy_enabled: false
        advisor:
          enabled: true
          # proxy_enabled: not-this-one
        """
        let out = SetupManager.proxyEnabledUpdating(yaml, enabled: true)
        XCTAssertTrue(out.contains("proxy_enabled: true"))
        XCTAssertTrue(out.contains("# user config"))
        XCTAssertTrue(out.contains("net_sample_interval_ms: 2000"))
        XCTAssertTrue(out.contains("advisor:\n  enabled: true"))
        // The commented lookalike inside the advisor block must survive
        // untouched — only the real top-level key flips.
        XCTAssertTrue(out.contains("# proxy_enabled: not-this-one"))
        XCTAssertEqual(out.components(separatedBy: "proxy_enabled:").count - 1, 2)
    }

    func testProxyEnableAppendsWhenAbsent() {
        let out = SetupManager.proxyEnabledUpdating("advisor:\n  enabled: false\n", enabled: true)
        XCTAssertTrue(out.hasPrefix("advisor:\n  enabled: false\n"))
        XCTAssertTrue(out.contains("proxy_enabled: true"))
    }

    func testProxyEnableOnEmptyConfig() {
        let out = SetupManager.proxyEnabledUpdating("", enabled: true)
        XCTAssertTrue(out.contains("proxy_enabled: true"))
    }

    func testProxyDisableFlipsBack() {
        let out = SetupManager.proxyEnabledUpdating("proxy_enabled: true\n", enabled: false)
        XCTAssertEqual(out, "proxy_enabled: false\n")
    }

    // MARK: focus-or-open scripts

    func testTabMatchIdentifiesConsoleTabs() {
        XCTAssertEqual(ConsoleOpener.tabMatch(port: 8443), "127.0.0.1:8443/dashboard")
    }

    func testFocusScriptTargetsExistingTab() {
        for browser in ["com.apple.Safari", "com.google.Chrome"] {
            let script = ConsoleOpener.focusScript(browserBundleID: browser, match: "127.0.0.1:8443/dashboard",
                                                   url: "http://127.0.0.1:8443/dashboard/#ct=abc")
            XCTAssertNotNil(script, "missing script for \(browser)")
            XCTAssertTrue(script!.contains("127.0.0.1:8443/dashboard"), "script must match the console URL")
            XCTAssertTrue(script!.contains("activate"), "script must raise the browser")
            XCTAssertTrue(script!.contains("\"focused\""), "script must report success for the fallback check")
        }
    }

    func testFocusScriptNilForUnknownBrowsers() {
        XCTAssertNil(ConsoleOpener.focusScript(browserBundleID: "com.arc.browser", match: "x", url: "x"))
        XCTAssertNil(ConsoleOpener.focusScript(browserBundleID: "org.mozilla.firefox", match: "x", url: "x"))
    }

    /// An expired console tab only recovers when the focused tab receives the
    /// fresh #ct= token, so the script loads the full URL before activating.
    func testFocusScriptLoadsFreshURLBeforeActivating() {
        let url = "http://127.0.0.1:8443/dashboard/#ct=fresh&tab=egress"
        let expect = [
            "com.apple.Safari": "set URL of t to \"\(url)\"",
            "com.google.Chrome": "set URL of (tab i of w) to \"\(url)\"",
        ]
        for (browser, line) in expect {
            let script = ConsoleOpener.focusScript(browserBundleID: browser, match: "127.0.0.1:8443/dashboard", url: url)!
            XCTAssertTrue(script.contains(line), "\(browser) script must load the fresh URL")
            let set = script.range(of: "set URL")!.lowerBound
            let raise = script.range(of: "activate")!.lowerBound
            XCTAssertTrue(set < raise, "\(browser) must load the URL before activating")
        }
    }

    func testFocusScriptEscapesURLForAppleScriptLiteral() {
        let url = #"http://127.0.0.1:8443/dashboard/#ct=a"b\c"#
        let script = ConsoleOpener.focusScript(browserBundleID: "com.google.Chrome", match: "x", url: url)!
        XCTAssertTrue(script.contains(#"to "http://127.0.0.1:8443/dashboard/#ct=a\"b\\c""#), script)
        XCTAssertEqual(ConsoleOpener.appleScriptLiteral(#"a"b\c"#), #"a\"b\\c"#)
    }
}
