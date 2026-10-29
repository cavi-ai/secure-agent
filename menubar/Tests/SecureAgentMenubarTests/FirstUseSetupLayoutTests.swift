import AppKit
import ServiceManagement
import SwiftUI
import XCTest
@testable import SecureAgentMenubar

/// Production views in task-owned native windows, with synthetic setup facts.
/// No hook, permission, routing or credential action is invoked by this test.
@MainActor
final class FirstUseSetupLayoutTests: XCTestCase {
    func testSelectedFlowAndDegradedRecoveryInNativeWindow() async throws {
        _ = NSApplication.shared
        let priorPolicy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        NSApp.activate(ignoringOtherApps: true)
        defer { NSApp.setActivationPolicy(priorPolicy) }
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "FirstUseSetupLayoutTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults,
                                 plistPresent: { false }, openPane: { _ in XCTFail("No permission pane should open") },
                                 appURL: URL(fileURLWithPath: "/fixture/Secure Agent.app"), deferAutomaticTelemetry: true)
        let passed = FirstUseSetupState(daemonAvailable: true, installedHarnesses: ["claude"], probes: [
            CoverageProbeReceiptModel(harness: "claude", hookPath: "/synthetic/.claude/hooks/secret_guard.py", checkedAt: "Synthetic fixture time", state: "passed", detail: "Synthetic receipt: this manual installed-hook check does not prove a running agent invokes the hook.")
        ])
        setup.seedFirstUseForTesting(passed)
        let flow = FirstUseSetupFlow()
        let controller = NSHostingController(rootView: OnboardingView(setup: setup, appState: AppState(), flow: flow, refreshAutomatically: false, onDone: {}))
        let window = NSWindow(contentViewController: controller)
        window.isReleasedWhenClosed = false
        window.styleMask = [.titled, .closable, .resizable]
        window.title = "Synthetic first-use setup proof"
        window.setContentSize(NSSize(width: 560, height: 650))
        let view = try XCTUnwrap(window.contentView)
        defer { window.orderOut(nil); window.close() }
        window.makeKeyAndOrderFront(nil)
        await settle(view)
        try snapshot(view, name: "choose-default")
        let enter = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [],
            timestamp: 0, windowNumber: window.windowNumber, context: nil,
            characters: "\r", charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36))
        XCTAssertTrue(window.performKeyEquivalent(with: enter), "Return must activate Continue in the native window")
        await settle(view)
        XCTAssertEqual(flow.stage, .enable)
        try snapshot(view, name: "enable-default")
        flow.stage = .result
        await settle(view)
        try snapshot(view, name: "result-default")
        var unavailable = passed
        unavailable.daemonAvailable = false
        setup.seedFirstUseForTesting(unavailable)
        await settle(view)
        XCTAssertFalse(setup.firstUseState.result(for: flow.selectedHarness).passed)
        try snapshot(view, name: "result-unavailable")
        setup.seedFirstUseForTesting(passed)
        await settle(view)
        XCTAssertTrue(setup.firstUseState.result(for: flow.selectedHarness).passed)
        window.setContentSize(NSSize(width: 520, height: 580))
        await settle(view)
        assertFits(view, window: window)
        try snapshot(view, name: "result-recovered-minimum")
    }

    func testObservationAndMissingHookResultsAtMinimumSize() async throws {
        _ = NSApplication.shared
        let priorPolicy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        NSApp.activate(ignoringOtherApps: true)
        defer { NSApp.setActivationPolicy(priorPolicy) }
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "FirstUseSetupLayoutTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, plistPresent: { false },
                                 openPane: { _ in XCTFail("No permission pane should open") },
                                 appURL: URL(fileURLWithPath: "/fixture/Secure Agent.app"), deferAutomaticTelemetry: true)
        setup.seedFirstUseForTesting(FirstUseSetupState(daemonAvailable: true))
        for harness in ["claude", "cursor", "codex", "openclaw", "hermes", "opencode", "antigravity"] {
            for stage in [FirstUseSetupStage.enable, .result] {
                let controller = NSHostingController(rootView: OnboardingView(setup: setup, appState: AppState(),
                    flow: FirstUseSetupFlow(stage: stage, selectedHarness: harness), refreshAutomatically: false, onDone: {}))
                let window = NSWindow(contentViewController: controller)
                window.isReleasedWhenClosed = false
                window.setContentSize(NSSize(width: 520, height: 580))
                let view = try XCTUnwrap(window.contentView)
                window.makeKeyAndOrderFront(nil)
                await settle(view)
                assertFits(view, window: window)
                try snapshot(view, name: "minimum-\(stage)-\(harness)")
                window.orderOut(nil); window.close()
            }
        }
    }

    func testFirstSessionOffersExplicitEvidenceChoices() async throws {
        _ = NSApplication.shared
        let priorPolicy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        NSApp.activate(ignoringOtherApps: true)
        defer { NSApp.setActivationPolicy(priorPolicy) }
        let oldIcon = NSApp.applicationIconImage
        let artwork = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("daemon/internal/api/web_dist/brand-icon.png")
        NSApp.applicationIconImage = try XCTUnwrap(NSImage(contentsOf: artwork))
        defer { NSApp.applicationIconImage = oldIcon }
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "FirstSessionLayout.\(UUID().uuidString)"))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, plistPresent: { false },
            openPane: { _ in XCTFail("No permission change") },
            appURL: URL(fileURLWithPath: "/fixture/Secure Agent.app"), deferAutomaticTelemetry: true)
        let first = try coverage(id: "first", workspace: "/workspace/api")
        let second = try coverage(id: "second", workspace: "/workspace/web")
        let foreign = try coverage(id: "foreign", workspace: "/workspace/other", harness: "cursor")
        var facts = FirstUseSetupState(daemonAvailable: true, installedHarnesses: ["claude"], probes: [
            CoverageProbeReceiptModel(harness: "claude", hookPath: "/synthetic/.claude/hooks/secret_guard.py",
                checkedAt: "2026-10-15T12:00:00Z", state: "passed", detail: "Manual round trip observed; live session activity is checked separately.")
        ], sessions: [first, second, foreign])
        var empty = facts
        empty.sessions = []
        setup.seedFirstUseForTesting(empty)
        let appState = AppState(client: StubDaemonClient())
        let ready = StatusResponse(running: true, uptime: "1m", activeAgents: 0, agents: [],
            proxyEnabled: true, proxyPort: 8443, uninspectedEgress: 0, firewallStats: nil)
        appState.seedForTesting(status: ready)
        var opened: [ConsoleDestination?] = []
        let controller = NSHostingController(rootView: OnboardingView(setup: setup, appState: appState,
            flow: FirstUseSetupFlow(stage: .result), refreshAutomatically: false,
            onOpenConsole: { opened.append($0) }, onDone: {}))
        let window = NSWindow(contentViewController: controller)
        window.isReleasedWhenClosed = false
        window.setContentSize(NSSize(width: 560, height: 900))
        defer { window.orderOut(nil); window.close() }
        window.makeKeyAndOrderFront(nil)
        await settle(controller.view)
        func openWithKey(_ key: String) throws -> Bool {
            let event = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [.command],
                timestamp: 0, windowNumber: window.windowNumber, context: nil,
                characters: key, charactersIgnoringModifiers: key, isARepeat: false, keyCode: ["1": 18, "2": 19, "0": 29][key] ?? 0))
            return window.performKeyEquivalent(with: event)
        }
        _ = try openWithKey("1")
        XCTAssertTrue(opened.isEmpty, "A passed manual check cannot invent a live session")
        try snapshot(controller.view, name: "first-session-empty")
        setup.seedFirstUseForTesting(facts)
        await settle(controller.view)
        XCTAssertTrue(try openWithKey("1"))
        XCTAssertTrue(try openWithKey("2"))
        XCTAssertEqual(opened, [.session("first"), .session("second")])
        try snapshot(controller.view, name: "first-session-choices")
        facts.sessionsUnavailable = true
        setup.seedFirstUseForTesting(facts)
        await settle(controller.view)
        _ = try openWithKey("1")
        XCTAssertEqual(opened.count, 2, "Stale observations cannot provide a current setup handoff")
        try snapshot(controller.view, name: "first-session-stale")
        facts.sessionsUnavailable = false
        facts.sessionsTruncated = true
        setup.seedFirstUseForTesting(facts)
        await settle(controller.view)
        XCTAssertTrue(try openWithKey("0"))
        XCTAssertEqual(opened.count, 3)
        XCTAssertEqual(opened.last, .some(nil))
        appState.seedForTesting(status: StatusResponse(running: true, uptime: "1m", activeAgents: 0, agents: [],
            proxyEnabled: false, proxyPort: 0, uninspectedEgress: 0, firewallStats: nil))
        await settle(controller.view)
        _ = try openWithKey("1")
        XCTAssertEqual(opened.count, 3, "Console-off recovery must not enable routing or open a stale port")
        window.setContentSize(NSSize(width: 520, height: 580))
        await settle(controller.view)
        assertFits(controller.view, window: window)
        try snapshot(controller.view, name: "first-session-console-off")
    }

    private func coverage(id: String?, workspace: String, harness: String = "claude") throws -> SessionCoverageModel {
        let path: [String: Any] = ["supported": true, "state": "observed", "detail": "Only this recorded invocation", "last_seen": "2026-10-15T12:00:00Z"]
        var record: [String: Any] = ["harness": harness, "workspace": workspace, "root_pid": 123, "identity_basis": "hook", "guard": path, "trace": path, "payload": ["supported": true, "state": "off", "detail": "Routing disabled"]]
        if let id { record["session_id"] = id }
        return try JSONDecoder().decode(SessionCoverageModel.self, from: JSONSerialization.data(withJSONObject: record))
    }

    private func settle(_ view: NSView) async {
        try? await Task.sleep(for: .milliseconds(250))
        pumpNativeRunLoop()
        NSApp.updateWindows()
        view.layoutSubtreeIfNeeded()
        view.displayIfNeeded()
    }

    private func pumpNativeRunLoop() { RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05)) }

    private func nodes(_ root: Any) -> [any NSAccessibilityProtocol] {
        var result: [any NSAccessibilityProtocol] = []
        var seen = Set<ObjectIdentifier>()
        func visit(_ object: Any) {
            guard let node = object as? any NSAccessibilityProtocol,
                  seen.insert(ObjectIdentifier(node)).inserted else { return }
            result.append(node)
            (node.accessibilityChildren() ?? []).forEach(visit)
            if let view = object as? NSView { view.subviews.forEach(visit) }
        }
        visit(root)
        return result
    }

    private func assertFits(_ view: NSView, window: NSWindow) {
        let bounds = window.convertToScreen(view.bounds)
        for node in nodes(view) where [.button, .popUpButton, .checkBox].contains(node.accessibilityRole()) {
            let frame = node.accessibilityFrame()
            guard frame.width > 0 else { continue }
            XCTAssertGreaterThanOrEqual(frame.minX, bounds.minX - 1, node.accessibilityLabel() ?? "")
            XCTAssertLessThanOrEqual(frame.maxX, bounds.maxX + 1, node.accessibilityLabel() ?? "")
        }
    }

    private func snapshot(_ view: NSView, name: String) throws {
        let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: bitmap)
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("dist/setup-qa")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:])).write(to: root.appendingPathComponent(name + ".png"))
        // Optional on-machine window proof. CI's layout artifact above does
        // not include every native composited layer. Never request a grant.
        if let directory = ProcessInfo.processInfo.environment["SECURE_AGENT_SETUP_SCREENSHOTS"],
           let window = view.window {
            guard CGPreflightScreenCaptureAccess() else {
                print("SETUP_WINDOW_CAPTURE_UNAVAILABLE: Screen Recording access unavailable")
                return
            }
            let destination = URL(fileURLWithPath: directory)
            try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
            process.arguments = ["-x", "-o", "-l", String(window.windowNumber), destination.appendingPathComponent(name + ".png").path]
            try process.run()
            process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0, "Task-owned native window capture failed")
        }
    }
}
