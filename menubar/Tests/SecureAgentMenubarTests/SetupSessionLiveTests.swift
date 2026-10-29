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
        let withClaude = ProcessInfo.processInfo.environment["SECURE_AGENT_SETUP_E2E_WITH_CLAUDE"] == "1"
        if withClaude { app.testHookSkipPromptDialog = true }
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
        let flow = FirstUseSetupFlow(stage: .result, selectedHarness: "codex")
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
        XCTAssertEqual(coverage.rootPID, try childPID(root, marker: "harness-started"))
        XCTAssertEqual(coverage.guardPath.state, "not-observed")
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
        func captureConsoleState() async {
            // Retain fixture evidence without URLs, credentials or payloads.
            if let snapshot = try? await web.evaluateJavaScript("""
                JSON.stringify({selected: window.SA?.selectedSessionId, view: window.SA?.sessionView,
                  traceState: window.SA?.sessionTimelineState,
                  trace: window.SA?.sessionTimeline?.map(e => ({session: e.session_id, kind: e.kind, tool: e.tool, call: e.call_id})),
                  text: document.querySelector('#session-detail')?.textContent.slice(0,8000)})
                """) as? String {
                try? snapshot.write(to: root.appendingPathComponent("console-state.json"), atomically: true, encoding: .utf8)
            }
        }
        do {
            try await wait("real console renders attributed tool evidence", seconds: 45) {
                _ = try? await web.evaluateJavaScript("document.querySelector('[data-action=\"session-view\"][data-view=\"trace\"]')?.click()")
                let result = try? await web.evaluateJavaScript("""
                    window.SA?.selectedSessionId === \(expectedID) && window.SA?.sessionView === 'trace' &&
                    window.SA?.sessionTimeline?.some(e => e.session_id === \(expectedID) && e.kind === 12 &&
                        e.call_id && e.tool && e.tool !== 'wait' &&
                        Array.from(document.querySelectorAll('#session-detail .session-detail-body .wf-name'))
                          .some(label => label.getClientRects().length && label.firstChild?.textContent === e.tool))
                    """)
                return result as? Bool == true
            }
        } catch {
            await captureConsoleState()
            throw error
        }
        await captureConsoleState()
        if withClaude {
            let hooks = try XCTUnwrap(ProcessInfo.processInfo.environment["SECURE_AGENT_SETUP_E2E_HOOKS_DIR"])
            try HookRegistry.installSelectedHooks(harness: "claude", bundledDir: hooks, home: home)
            let guardModes = URL(fileURLWithPath: home).appendingPathComponent(".config/secure-agent/guard-modes.json")
            try FileManager.default.createDirectory(at: guardModes.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(["env-files": "prompt"]).write(to: guardModes, options: .atomic)
            try stage("isolated Claude hooks installed")
            try Data().write(to: root.appendingPathComponent("claude-ready"))
            try await wait("Claude process started", seconds: 150) {
                FileManager.default.fileExists(atPath: root.appendingPathComponent("claude-started").path)
            }
            let claudePID = try childPID(root, marker: "claude-started")
            let claudeExecutable = try String(contentsOf: root.appendingPathComponent("claude-executable"), encoding: .utf8)
            app.refresh()
            try await wait("isolated Claude executable is tagged by the daemon", seconds: 30) {
                return app.status?.agents?.contains { agent in
                    agent.pid == claudePID && agent.name == "claude" &&
                        URL(fileURLWithPath: agent.exePath ?? "").lastPathComponent ==
                        URL(fileURLWithPath: claudeExecutable).lastPathComponent
                } == true
            }
            try stage("waiting for native allow decision")
            try await wait("Claude allow request", seconds: 90) {
                guard let pending = app.pendingGuard else { return false }
                return pending.path.hasSuffix("/.env.allowed") && pending.sessionID?.isEmpty == false
            }
            guard let allowedRequest = app.pendingGuard else { throw Failure.timeout("Claude allow request") }
            XCTAssertEqual(allowedRequest.agent, "claude")
            XCTAssertEqual(allowedRequest.ruleID, "env-files")
            await app.resolvePendingGuard(id: allowedRequest.id, verdict: "allow", scope: "once")
            try stage("waiting for native deny decision")
            try await wait("Claude deny request", seconds: 90) {
                guard let pending = app.pendingGuard else { return false }
                return pending.path.hasSuffix("/.env.denied") && pending.sessionID?.isEmpty == false
            }
            guard let deniedRequest = app.pendingGuard else { throw Failure.timeout("Claude deny request") }
            XCTAssertEqual(deniedRequest.agent, "claude")
            XCTAssertEqual(deniedRequest.ruleID, "env-files")
            await app.resolvePendingGuard(id: deniedRequest.id, verdict: "deny", scope: "once")
            try await wait("real Claude tool results and report checks", seconds: 200) {
                FileManager.default.fileExists(atPath: root.appendingPathComponent("claude-finished").path)
            }
            let claudeID = try XCTUnwrap(self.claudeSessionID(in: root.appendingPathComponent("claude-stream.jsonl")))
            XCTAssertNotEqual(claudeID, id, "Codex and Claude must retain separate durable session identities")
            try stage("waiting for Claude session coverage")
            try await wait("attributed Claude trace and guard activity", seconds: 45) {
                await setup.refreshState()
                return setup.firstUseState.sessions.contains {
                    $0.sessionID == claudeID && $0.harness == "claude" &&
                        $0.workspace == root.appendingPathComponent("project").path &&
                        $0.trace.state == "observed" && $0.guardPath.state == "observed"
                }
            }
            let claudeCoverage = try XCTUnwrap(setup.firstUseState.sessions.first { $0.sessionID == claudeID })
            XCTAssertEqual(claudeCoverage.harness, "claude")
            XCTAssertEqual(claudeCoverage.workspace, root.appendingPathComponent("project").path)
            XCTAssertEqual(claudeCoverage.rootPID, claudePID)
            XCTAssertEqual(claudeCoverage.trace.state, "observed")
            XCTAssertEqual(claudeCoverage.guardPath.state, "observed")
            XCTAssertNotEqual(claudeCoverage.payload.state, "observed")
            flow.selectedHarness = "claude"
            opened.removeAll()
            try await settle()
            XCTAssertTrue(try key("1", code: 18, modifiers: .command, in: window))
            XCTAssertEqual(opened, [.session(claudeID)])
            let claudeExpectedID = String(data: try JSONSerialization.data(withJSONObject: claudeID, options: .fragmentsAllowed), encoding: .utf8)!
            try await wait("console selects Claude durable session", seconds: 45) {
                let result = try? await web.evaluateJavaScript("window.SA?.selectedSessionId || ''")
                return result as? String == claudeID
            }
            try stage("waiting for rendered Claude tool evidence")
            try await wait("real console renders Claude tool evidence", seconds: 45) {
                _ = try? await web.evaluateJavaScript("document.querySelector('[data-action=\"session-view\"][data-view=\"trace\"]')?.click()")
                let result = try? await web.evaluateJavaScript("""
                    window.SA?.selectedSessionId === \(claudeExpectedID) && window.SA?.sessionView === 'trace' &&
                    window.SA?.sessionTimeline?.some(e => e.session_id === \(claudeExpectedID) && e.kind === 12 &&
                        e.call_id && e.tool && e.tool.toLowerCase() === 'read' &&
                        Array.from(document.querySelectorAll('#session-detail .session-detail-body .wf-name'))
                          .some(label => label.getClientRects().length && label.firstChild?.textContent?.toLowerCase() === e.tool.toLowerCase()))
                    """)
                return result as? Bool == true
            }
            await captureConsoleState()
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

    private func claudeSessionID(in url: URL) -> String? {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") {
            if let row = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
               row["type"] as? String == "system", row["subtype"] as? String == "init" {
                return row["session_id"] as? String
            }
        }
        return nil
    }

    private func childPID(_ root: URL, marker: String) throws -> Int32 {
        let value = try String(contentsOf: root.appendingPathComponent(marker), encoding: .utf8)
        return try XCTUnwrap(Int32(value))
    }

}
