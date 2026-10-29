import AppKit
import SwiftUI
import XCTest
@testable import SecureAgentMenubar

@MainActor
private final class TrafficChoice: ObservableObject {
    @Published var harness = "claude"
}

@MainActor
private struct TrafficSettingsHost: View {
    @ObservedObject var choice: TrafficChoice
    let setup: SetupManager
    var onSetup: (String) -> Void

    var body: some View {
        Form {
            HarnessTrafficSetupSection(setup: setup, harness: $choice.harness, onSetup: onSetup)
        }.formStyle(.grouped)
    }
}

/// Exercises the production SwiftUI hierarchy in a test-owned native window.
/// Only navigation is changed; fixture rule data never leaves the test.
@MainActor
final class SettingsLayoutTests: XCTestCase {
    func testTrafficSelectionCoversProvidersWithoutChangingTheirConfiguration() async throws {
        _ = NSApplication.shared
        let policy = NSApp.activationPolicy()
        NSApp.setActivationPolicy(.regular)
        NSApp.finishLaunching()
        defer { NSApp.setActivationPolicy(policy) }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let suite = "TrafficSettingsTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, configurationHome: root.path,
            plistPresent: { false }, openPane: { _ in XCTFail("No permissions should change") },
            appURL: URL(fileURLWithPath: "/fixture/Secure Agent.app"), deferAutomaticTelemetry: true)
        setup.runProcess = { _, _ in XCTFail("Choosing an agent must not launch a process"); return (-1, "", "") }
        let choice = TrafficChoice()
        var opened: [String] = []
        let controller = NSHostingController(rootView: TrafficSettingsHost(choice: choice, setup: setup,
            onSetup: { opened.append($0) }))
        let window = NSWindow(contentViewController: controller)
        window.isReleasedWhenClosed = false
        defer { window.orderOut(nil); window.close() }
        window.setContentSize(NSSize(width: 564, height: 420))
        window.makeKeyAndOrderFront(nil)
        choice.harness = "codex"
        await settle(controller.view)
        XCTAssertFalse(setup.isAgentRoutingConfigured)
        try snapshot(controller.view, name: "traffic-codex-unavailable")

        let snippet = URL(fileURLWithPath: setup.agentRoutingSnippetPath)
        try FileManager.default.createDirectory(at: snippet.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("# inert routing fixture\n".utf8).write(to: snippet)
        XCTAssertTrue(setup.isAgentRoutingConfigured)
        XCTAssertTrue(Set(SetupManager.knownAgents.map(\.name)).isSuperset(of: FirstUseSetupState.hookHarnesses))
        for agent in SetupManager.knownAgents {
            choice.harness = agent.name
            await settle(controller.view)
            XCTAssertEqual(choice.harness, agent.name)
            XCTAssertTrue(opened.isEmpty, "Choosing an agent must not install hooks")
            XCTAssertFalse(setup.claudeRoutingApplied, "Choosing an agent must not apply routing")
            if FirstUseSetupState.supportsHook(agent.name) || agent.name == "aider" {
                for size in [NSSize(width: 564, height: 420), NSSize(width: 664, height: 540)] {
                    window.setContentSize(size)
                    await settle(controller.view)
                    assertHorizontalFit(controller.view, window: window)
                    try snapshot(controller.view, name: "traffic-\(agent.name)-\(Int(size.width))")
                }
            }
        }
        for harness in FirstUseSetupState.hookHarnesses {
            XCTAssertFalse(FileManager.default.fileExists(atPath: HookRegistry.hookDirectory(harness: harness, home: root.path)))
        }
        XCTAssertEqual(try Data(contentsOf: snippet), Data("# inert routing fixture\n".utf8))
    }

    func testNativeSettingsAtMinimumAndDefaultSizes() async throws {
        _ = NSApplication.shared
        let priorPolicy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        defer { NSApp.setActivationPolicy(priorPolicy) }
        NSApp.finishLaunching()
        let priorTab = SettingsNavigation.shared.tab
        SettingsNavigation.shared.tab = .fileGuard
        let state = AppState.preview()
        #if DEBUG
        state.seedForTesting(status: StatusResponse(
            running: true, uptime: "test fixture", activeAgents: 0,
            firewallStats: Dictionary(uniqueKeysWithValues: (0..<16).map {
                (String(format: "fixture-rule-%02d", $0), RuleStatModel(
                    wouldBlock: $0, blocked: 0, legit: 1, mode: $0 < 4 ? "block" : "monitor",
                    type: $0 < 10 ? "vendor-key" : "cloud-key"))
            })))
        #endif
        let priorWindows = Set(NSApp.windows.map(ObjectIdentifier.init))
        let controller = SettingsWindowController()
        controller.show(state: state)
        let window = try XCTUnwrap(NSApp.windows.first { !priorWindows.contains(ObjectIdentifier($0)) })
        let hosting = try XCTUnwrap(window.contentView as? NSHostingView<SettingsView>)
        XCTAssertEqual(hosting.bounds.size, NSSize(width: 860, height: 640))
        XCTAssertEqual(window.contentMinSize, NSSize(width: 760, height: 520))
        window.setContentSize(window.contentMinSize)
        defer {
            window.orderOut(nil)
            window.close()
            SettingsNavigation.shared.tab = priorTab
        }
        await settle(hosting)
        drainApplicationEvents()
        print("SETTINGS_NATIVE_FRAME outer=\(window.frame) content=\(hosting.frame) bounds=\(hosting.bounds)")
        XCTAssertEqual(hosting.bounds.size, NSSize(width: 760, height: 520))
        XCTAssertTrue(segmentedControls(hosting).isEmpty, "Pages are sidebar entries, not segmented sub-tabs")

        // SwiftUI draws menu pickers and switches with AppKit controls on
        // some macOS versions and natively on others, so control-level
        // behavior is covered by unit tests; this checks layout only.
        // Telemetry is left out: opening it runs the Doctor's system probes.
        for tab in SettingsTab.allCases where tab != .telemetry && tab != .analysis {
            SettingsNavigation.shared.tab = tab
            await settle(hosting)
            assertHorizontalFit(hosting, window: window)
            try snapshot(hosting, name: "minimum-\(tab)")
            scrollDetailToEnd(hosting)
            await settle(hosting)
            assertHorizontalFit(hosting, window: window)
            try snapshot(hosting, name: "minimum-\(tab)-end")
        }

        SettingsNavigation.shared.tab = .analysis
        await settle(hosting)
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "minimum-analysis-top")
        scrollDetailToEnd(hosting)
        await settle(hosting)
        try snapshot(hosting, name: "minimum-analysis-end")

        window.setContentSize(NSSize(width: 860, height: 640))
        scrollDetailToStart(hosting)
        await settle(hosting)
        let analysisScroll = try XCTUnwrap(detailScroll(hosting))
        let document = try XCTUnwrap(analysisScroll.documentView)
        XCTAssertLessThanOrEqual(document.bounds.height, analysisScroll.contentView.bounds.height + 1,
                                 "Collapsed Analysis configuration must fit without scrolling at default size")
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "default-analysis")
    }

    private func settle(_ view: NSView) async {
        try? await Task.sleep(for: .milliseconds(250))
        NSApp.updateWindows()
        pumpNativeRunLoop()
        view.layoutSubtreeIfNeeded()
        view.displayIfNeeded()
    }

    func testAdvisorOptionsExpandInNativeSettings() async throws {
        _ = NSApplication.shared
        let priorTab = SettingsNavigation.shared.tab
        SettingsNavigation.shared.tab = .analysis
        defer { SettingsNavigation.shared.tab = priorTab }
        let controller = NSHostingController(rootView: SettingsView(state: .preview(), advisorOptionsExpanded: true))
        let window = NSWindow(contentViewController: controller)
        window.isReleasedWhenClosed = false
        window.setContentSize(NSSize(width: 760, height: 520))
        let hosting = try XCTUnwrap(window.contentView as? NSHostingView<SettingsView>)
        defer { window.orderOut(nil); window.close() }
        window.makeKeyAndOrderFront(nil)
        await settle(hosting)
        scrollDetailToEnd(hosting)
        await settle(hosting)
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "advisor-options-expanded")
    }

    private func pumpNativeRunLoop() {
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
    }

    private func nodes(_ root: Any) -> [any NSAccessibilityProtocol] {
        var result: [any NSAccessibilityProtocol] = []
        var seen = Set<ObjectIdentifier>()
        func visit(_ object: Any) {
            guard let accessible = object as? any NSAccessibilityProtocol,
                  seen.insert(ObjectIdentifier(accessible)).inserted else { return }
            result.append(accessible)
            (accessible.accessibilityChildren() ?? []).forEach(visit)
            if let view = object as? NSView { view.subviews.forEach(visit) }
        }
        visit(root)
        return result
    }

    private func descendants(_ view: NSView) -> [NSView] {
        [view] + view.subviews.flatMap(descendants)
    }

    private func detailScroll(_ view: NSView) -> NSScrollView? {
        descendants(view).compactMap { $0 as? NSScrollView }.first {
            view.convert($0.bounds, from: $0).minX >= 196
        }
    }

    /// Segmented controls in the detail pane (the Updates channel picker is
    /// the one deliberate segmented control and is not on the first page).
    private func segmentedControls(_ view: NSView) -> [NSSegmentedControl] {
        descendants(view).compactMap { $0 as? NSSegmentedControl }
    }

    private func scrollDetailToEnd(_ view: NSView) {
        guard let scroll = detailScroll(view), let document = scroll.documentView else { return }
        document.scrollToVisible(NSRect(x: 0, y: document.bounds.maxY - 1, width: 1, height: 1))
    }

    private func scrollDetailToStart(_ view: NSView) {
        detailScroll(view)?.documentView?.scrollToVisible(NSRect(x: 0, y: 0, width: 1, height: 1))
    }

    private func assertHorizontalFit(_ view: NSView, window: NSWindow) {
        let bounds = window.convertToScreen(view.bounds)
        for node in nodes(view) {
            guard let role = node.accessibilityRole(),
                  [.button, .radioButton, .checkBox, .popUpButton].contains(role),
                  node.accessibilityFrame().width > 0 else { continue }
            let frame = node.accessibilityFrame()
            XCTAssertGreaterThanOrEqual(frame.minX, bounds.minX - 1, node.accessibilityLabel() ?? "")
            XCTAssertLessThanOrEqual(frame.maxX, bounds.maxX + 1, node.accessibilityLabel() ?? "")
        }
    }

    private func drainApplicationEvents() {
        for _ in 0..<100 {
            guard let event = NSApp.nextEvent(matching: .any, until: Date(timeIntervalSinceNow: 0.01),
                                            inMode: .default, dequeue: true) else { break }
            NSApp.sendEvent(event)
        }
    }

    private func snapshot(_ view: NSView, name: String) throws {
        // AppKit cacheDisplay omits some native composited layers; these are
        // content-layout artifacts, not substitutes for full-screen evidence.
        let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: bitmap)
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let directory = root.appendingPathComponent("dist/settings-qa/native-tests")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
            .write(to: directory.appendingPathComponent(name + ".png"))
    }
}
