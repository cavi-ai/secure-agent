import AppKit
import Combine
import SwiftUI
import XCTest
@testable import SecureAgentMenubar

@MainActor
final class HarnessHookSetupTests: XCTestCase {
    func testSettingsSetupWindowSelectsEachHarnessWhenReused() async throws {
        let policy = activateApplication()
        defer { NSApp.setActivationPolicy(policy) }
        let fixture = try Fixture()
        defer { fixture.remove() }
        let controller = OnboardingWindowController(setup: fixture.setup, preferences: fixture.defaults)
        controller.appState = AppState(client: StubDaemonClient())
        let prior = Set(NSApp.windows.map(ObjectIdentifier.init))
        defer { controller.close() }
        var openedWindow: NSWindow?
        for harness in ["codex", "openclaw"] {
            controller.show(harness: harness)
            let window = try XCTUnwrap(NSApp.windows.first { !prior.contains(ObjectIdentifier($0)) })
            await settle(try XCTUnwrap(window.contentView))
            XCTAssertEqual(controller.flow?.selectedHarness, harness)
            XCTAssertEqual(controller.flow?.stage, .enable)
            if let openedWindow { XCTAssertTrue(window === openedWindow) }
            openedWindow = window
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.home + "/.codex"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.home + "/.openclaw"))
    }

    func testCodexWizardWritesRegistrationAndPreservesUserHooks() async throws {
        let policy = activateApplication()
        defer { NSApp.setActivationPolicy(policy) }
        let fixture = try Fixture()
        defer { fixture.remove() }
        let config = URL(fileURLWithPath: fixture.home + "/.codex/hooks.json")
        try FileManager.default.createDirectory(at: config.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original = Data(#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"user-hook"}]}]}}"#.utf8)
        try original.write(to: config)
        let flow = FirstUseSetupFlow(stage: .enable, selectedHarness: "codex")
        let controller = NSHostingController(rootView: OnboardingView(setup: fixture.setup,
            appState: AppState(client: StubDaemonClient()), flow: flow, refreshAutomatically: false, onDone: {}))
        let window = makeWindow(controller)
        defer { window.close() }
        await settle(controller.view)
        try pressReturn(window)
        await settle(controller.view)
        XCTAssertEqual(flow.stage, .result)
        XCTAssertNil(fixture.setup.lastError)
        XCTAssertTrue(HookRegistry.selectedHooksInstalled(harness: "codex", home: fixture.home))
        XCTAssertEqual(original, try Data(contentsOf: URL(fileURLWithPath: config.path + ".bak-secure-agent")))
        XCTAssertTrue(try String(contentsOf: config, encoding: .utf8).contains("user-hook"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.home + "/.codex/config.toml"), "Codex owns hook enablement and trust")
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.home + "/.openclaw"))
        XCTAssertFalse(fixture.setup.firstUseState.result(for: "codex").passed)
        XCTAssertEqual(fixture.setup.firstUseState.result(for: "codex").title, "Hook activation required")
    }

    func testOpenClawWizardKeepsRejectedOrDisabledRegistrationRetryable() async throws {
        let policy = activateApplication()
        defer { NSApp.setActivationPolicy(policy) }
        let fixture = try Fixture()
        defer { fixture.remove() }
        let flow = FirstUseSetupFlow(stage: .enable, selectedHarness: "openclaw")
        let controller = NSHostingController(rootView: OnboardingView(setup: fixture.setup,
            appState: AppState(client: StubDaemonClient()), flow: flow, refreshAutomatically: false, onDone: {}))
        let window = makeWindow(controller)
        defer { window.close() }
        let source = HookRegistry.hookDirectory(harness: "openclaw", home: fixture.home) + "/index.mjs"
        for (exitStatus, enabled) in [(Int32(1), false), (Int32(0), false), (Int32(0), true)] {
            fixture.setup.runProcess = { _, args in
                if args.last == "--json" {
                    let data = try! JSONSerialization.data(withJSONObject: ["plugin": ["id": "secure-agent", "source": source, "enabled": enabled]])
                    return (0, String(decoding: data, as: UTF8.self), "")
                }
                XCTAssertEqual(Array(args.suffix(4)), ["openclaw", "plugins", "enable", "secure-agent"])
                XCTAssertFalse(args.contains("--force"))
                return (exitStatus, "", "")
            }
            await settle(controller.view)
            try pressReturn(window)
            await settle(controller.view)
            XCTAssertEqual(flow.stage, enabled ? .result : .enable)
            XCTAssertEqual(fixture.setup.lastError == nil, enabled)
            XCTAssertFalse(flow.installing)
            XCTAssertFalse(fixture.setup.firstUseState.result(for: "openclaw").passed)
        }
        XCTAssertTrue(HookRegistry.selectedHooksInstalled(harness: "openclaw", home: fixture.home))
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.home + "/.codex"))
    }

    func testOpenClawWizardWithNativeCLI() async throws {
        guard let cli = ProcessInfo.processInfo.environment["SECURE_AGENT_OPENCLAW_CLI"] else {
            throw XCTSkip("Set SECURE_AGENT_OPENCLAW_CLI to validate an installed OpenClaw CLI in an isolated profile")
        }
        let policy = activateApplication()
        defer { NSApp.setActivationPolicy(policy) }
        let fixture = try Fixture()
        defer { fixture.remove() }
        let home = fixture.home
        fixture.setup.runProcess = { bin, args in
            XCTAssertEqual(bin, "/usr/bin/env")
            var nativeArgs = args
            guard let command = nativeArgs.firstIndex(of: "openclaw") else { return (-1, "", "Missing OpenClaw command") }
            nativeArgs[command] = cli
            return await ProcessRunner.run("/bin/sh", ["-c", "cd \"$1\" && shift && exec /usr/bin/env -i \"$@\"",
                "hook-setup-test", home, "HOME=" + home] + nativeArgs)
        }
        let flow = FirstUseSetupFlow(stage: .enable, selectedHarness: "openclaw")
        let controller = NSHostingController(rootView: OnboardingView(setup: fixture.setup,
            appState: AppState(client: StubDaemonClient()), flow: flow, refreshAutomatically: false, onDone: {}))
        let window = makeWindow(controller)
        defer { window.close() }
        await settle(controller.view)
        let finished = expectation(description: "Native OpenClaw registration returned")
        let observation = flow.$installing.dropFirst().filter { !$0 }.sink { _ in finished.fulfill() }
        defer { observation.cancel() }
        try pressReturn(window)
        await fulfillment(of: [finished], timeout: 45)
        XCTAssertNil(fixture.setup.lastError)
        XCTAssertEqual(flow.stage, .result)
        XCTAssertTrue(HookRegistry.selectedHooksInstalled(harness: "openclaw", home: home))
        XCTAssertFalse(fixture.setup.firstUseState.result(for: "openclaw").passed)
        let config = try Data(contentsOf: URL(fileURLWithPath: home + "/.openclaw/openclaw.json"))
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: config, options: [.json5Allowed]) as? [String: Any])
        let plugins = try XCTUnwrap(root["plugins"] as? [String: Any])
        let entries = try XCTUnwrap(plugins["entries"] as? [String: Any])
        XCTAssertEqual((entries["secure-agent"] as? [String: Any])?["enabled"] as? Bool, true)
    }

    @MainActor
    private struct Fixture {
        let root: URL
        let home: String
        let setup: SetupManager
        let suite: String
        let defaults: UserDefaults

        init() throws {
            root = FileManager.default.temporaryDirectory.appendingPathComponent("hook setup '\(UUID().uuidString)")
            home = root.appendingPathComponent("home").path
            try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
            let app = root.appendingPathComponent("Secure Agent.app")
            let resources = app.appendingPathComponent("Contents/Resources")
            let helpers = app.appendingPathComponent("Contents/Helpers")
            try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
            try Data().write(to: helpers.appendingPathComponent("secure-agentd"))
            let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("plugin/hooks")
            try FileManager.default.copyItem(at: source, to: resources.appendingPathComponent("hooks"))
            suite = "HarnessHookSetupTests.\(UUID().uuidString)"
            defaults = UserDefaults(suiteName: suite)!
            setup = SetupManager(esService: FakeESService(), defaults: defaults, configurationHome: home,
                plistPresent: { false }, openPane: { _ in XCTFail("No permission change") },
                appURL: app, deferAutomaticTelemetry: true)
            setup.seedFirstUseForTesting(FirstUseSetupState(daemonAvailable: true))
        }

        func remove() {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
    }

    private func makeWindow<Content: View>(_ controller: NSHostingController<Content>) -> NSWindow {
        _ = NSApplication.shared
        NSApp.finishLaunching()
        let window = NSWindow(contentViewController: controller)
        window.isReleasedWhenClosed = false
        window.setContentSize(NSSize(width: 520, height: 580))
        window.makeKeyAndOrderFront(nil)
        return window
    }

    private func activateApplication() -> NSApplication.ActivationPolicy {
        _ = NSApplication.shared
        let policy = NSApp.activationPolicy()
        NSApp.setActivationPolicy(.regular)
        NSApp.finishLaunching()
        NSApp.activate(ignoringOtherApps: true)
        return policy
    }

    private func pressReturn(_ window: NSWindow) throws {
        let enter = try XCTUnwrap(NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [],
            timestamp: 0, windowNumber: window.windowNumber, context: nil,
            characters: "\r", charactersIgnoringModifiers: "\r", isARepeat: false, keyCode: 36))
        XCTAssertTrue(window.performKeyEquivalent(with: enter))
    }

    private func settle(_ view: NSView) async {
        try? await Task.sleep(for: .milliseconds(250))
        pumpRunLoop()
        NSApp.updateWindows()
        view.layoutSubtreeIfNeeded()
        view.displayIfNeeded()
    }

    private func pumpRunLoop() { RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05)) }

}
