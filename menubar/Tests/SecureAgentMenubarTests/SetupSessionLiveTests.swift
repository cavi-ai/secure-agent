import AppKit
import SwiftUI
import WebKit
import XCTest
@testable import SecureAgentMenubar

/// Run with `make test-setup-session-live`; never substitutes fixture telemetry.
@MainActor
final class SetupSessionLiveTests: XCTestCase {
    func testFreshProfileToLiveSessionEvidence() async throws {
        guard let path = ProcessInfo.processInfo.environment["SECURE_AGENT_SETUP_E2E_ROOT"] else {
            throw XCTSkip("Opt-in: make test-setup-session-live requires authenticated Codex and a graphical login")
        }
        let root = URL(fileURLWithPath: path)
        let expectedHome = root.appendingPathComponent("home").resolvingSymlinksInPath()
        let home = NSHomeDirectory()
        let actualHome = URL(fileURLWithPath: home).resolvingSymlinksInPath()
        let fileManagerHome = FileManager.default.homeDirectoryForCurrentUser.resolvingSymlinksInPath()
        // Fail closed before constructing anything that can read user state.
        XCTAssertEqual(actualHome, expectedHome)
        XCTAssertEqual(fileManagerHome, expectedHome)
        guard actualHome == expectedHome, fileManagerHome == expectedHome else {
            throw Failure.isolation
        }
        _ = NSApplication.shared
        let priorPolicy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        defer { NSApp.setActivationPolicy(priorPolicy) }
        let suite = "SetupSessionLiveTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertFalse(defaults.bool(forKey: "setupWizardDismissed"))
        let setup = SetupManager(defaults: defaults, deferAutomaticTelemetry: true)
        let client = DaemonClient()
        let app = AppState(client: client)
        app.start()
        defer { app.stop() }
        try await wait("fresh daemon") {
            await setup.refreshState()
            return setup.firstUseState.daemonAvailable && app.dashboardUnavailableReason == nil
        }
        XCTAssertTrue(setup.firstUseState.installedHarnesses.isEmpty)
        XCTAssertTrue(setup.firstUseState.probes.isEmpty)
        XCTAssertTrue(setup.firstUseState.sessions.isEmpty, "Fresh setup must not import host sessions")

        let webConfig = WKWebViewConfiguration()
        webConfig.websiteDataStore = .nonPersistent()
        let web = WKWebView(frame: NSRect(x: 0, y: 0, width: 1100, height: 800), configuration: webConfig)
        var opened: [ConsoleDestination?] = []
        let flow = FirstUseSetupFlow(selectedHarness: "codex")
        let view = OnboardingView(setup: setup, appState: app, flow: flow, refreshAutomatically: false,
            onOpenConsole: { destination in
                opened.append(destination)
                // Use the production URL builder and real console credential;
                // replace only OS browser dispatch with an isolated web view.
                guard let port = app.status?.proxyPort,
                      let token = try? String(contentsOfFile: home + "/.config/secure-agent/console-token", encoding: .utf8),
                      let url = ConsoleOpener.dashboardURL(port: port, token: token.trimmingCharacters(in: .whitespacesAndNewlines),
                                                          tab: "sessions", destination: destination) else {
                    XCTFail("Console handoff unavailable")
                    return
                }
                web.load(URLRequest(url: url))
            }, onDone: {})
        let controller = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: controller)
        window.isReleasedWhenClosed = false
        window.setContentSize(NSSize(width: 560, height: 900))
        window.makeKeyAndOrderFront(nil)
        defer { web.stopLoading(); window.orderOut(nil); window.close() }
        try await settle()
        XCTAssertTrue(try key("\r", code: 36, in: window))
        try await settle()
        XCTAssertEqual(flow.stage, .result)
        _ = try key("1", code: 18, modifiers: .command, in: window)
        XCTAssertTrue(opened.isEmpty, "Empty setup cannot invent session evidence")
        try FirstUseSetupState.sampleTask.write(to: root.appendingPathComponent("sample-task"), atomically: true, encoding: .utf8)
        try Data().write(to: root.appendingPathComponent("ready"))
        func stage(_ name: String) throws {
            try name.write(to: root.appendingPathComponent("stage"), atomically: true, encoding: .utf8)
        }

        var harnessID: String?
        try stage("waiting for attributed live trace in Setup")
        try await wait("live harness identity and attributed activity", seconds: 120) {
            harnessID = self.threadID(in: root.appendingPathComponent("harness.jsonl"))
            // Same production refresh as the Setup button, with no seeded
            // state or client stub. The evidence action below is native.
            await setup.refreshState()
            try await self.settle()
            return setup.firstUseState.sessions.contains {
                $0.sessionID == harnessID && $0.harness == "codex" && $0.trace.state == "observed"
            }
        }
        let id = try XCTUnwrap(harnessID)
        let coverage = try XCTUnwrap(setup.firstUseState.sessions.first { $0.sessionID == id })
        XCTAssertEqual(coverage.workspace, root.appendingPathComponent("project").path)
        XCTAssertEqual(coverage.guardPath.state, "unsupported")
        XCTAssertNotEqual(coverage.payload.state, "observed")
        XCTAssertFalse(setup.firstUseState.sessionsUnavailable)
        XCTAssertFalse(setup.firstUseState.result(for: "codex").passed, "Observed trace is not a hook check")
        XCTAssertTrue(try key("1", code: 18, modifiers: .command, in: window))
        XCTAssertEqual(opened, [.session(id)])

        try stage("waiting for selected session in console")
        try await wait("console selects the harness's durable session", seconds: 45) {
            let result = try? await web.evaluateJavaScript("window.SA?.selectedSessionId || ''")
            return result as? String == id
        }
        let expectedID = String(data: try JSONSerialization.data(withJSONObject: id, options: .fragmentsAllowed), encoding: .utf8)!
        try stage("waiting for rendered tool evidence in console")
        try await wait("real console renders attributed tool evidence", seconds: 45) {
            _ = try? await web.evaluateJavaScript("document.querySelector('[data-action=\"session-view\"][data-view=\"trace\"]')?.click()")
            let result = try? await web.evaluateJavaScript("""
                window.SA?.selectedSessionId === \(expectedID) &&
                window.SA?.sessionTimeline?.some(e => e.session_id === \(expectedID) && e.kind === 12 &&
                    e.call_id && e.tool &&
                    document.querySelector('#session-detail .session-detail-body')?.textContent.includes(e.tool))
                """)
            return result as? Bool == true
        }
        try stage("native session evidence assertions passed")
    }

    private enum Failure: Error { case isolation, timeout(String) }

    private func wait(_ description: String, seconds: Double = 30,
                      until condition: () async throws -> Bool) async throws {
        let deadline = Date().addingTimeInterval(seconds)
        repeat {
            if try await condition() { return }
            try await Task.sleep(for: .milliseconds(500))
        } while Date() < deadline
        XCTFail("Timed out waiting for \(description)")
        throw Failure.timeout(description)
    }

    private func settle() async throws {
        try await Task.sleep(for: .milliseconds(250))
        renderWindows()
    }

    private func renderWindows() {
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
        NSApp.updateWindows()
        for window in NSApp.windows {
            window.contentView?.layoutSubtreeIfNeeded()
            window.contentView?.displayIfNeeded()
        }
    }

    private func key(_ text: String, code: UInt16, modifiers: NSEvent.ModifierFlags = [], in window: NSWindow) throws -> Bool {
        let event = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: modifiers,
            timestamp: 0, windowNumber: window.windowNumber, context: nil, characters: text,
            charactersIgnoringModifiers: text, isARepeat: false, keyCode: code))
        return window.performKeyEquivalent(with: event)
    }

    private func threadID(in url: URL) -> String? {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") {
            if let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
               row["type"] as? String == "thread.started" { return row["thread_id"] as? String }
        }
        return nil
    }

}
