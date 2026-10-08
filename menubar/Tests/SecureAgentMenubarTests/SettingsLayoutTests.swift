import AppKit
import SwiftUI
import XCTest
@testable import SecureAgentMenubar

/// Exercises the production SwiftUI hierarchy in a test-owned native window.
/// Only navigation is changed; fixture rule data never leaves the test.
@MainActor
final class SettingsLayoutTests: XCTestCase {
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

        // File Guard: one mode menu per guarded path type.
        let guardMenus = menus(hosting)
        XCTAssertEqual(guardMenus.count, SettingsView.guardRules.count)
        XCTAssertTrue(guardMenus.allSatisfy { ["Monitor", "Prompt", "Deny"].contains($0.accessibilityValue() as? String) })
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "minimum-file-guard")
        scrollDetailToEnd(hosting)
        await settle(hosting)
        assertOnScreen(try XCTUnwrap(menus(hosting).last), in: hosting, window: window)

        // The sidebar is keyboard-navigable: Down Arrow moves to Egress Firewall.
        let sidebar = try XCTUnwrap(sidebarTable(hosting))
        XCTAssertTrue(window.makeFirstResponder(sidebar))
        try sendKey("\u{F701}", keyCode: 125, window: window)
        drainApplicationEvents()
        await settle(hosting)
        XCTAssertEqual(SettingsNavigation.shared.tab, .firewall, "Down Arrow in the sidebar must select the next page")

        // Egress Firewall: one switch per rule, on exactly where the rule blocks.
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "minimum-firewall-top")
        scrollDetailToEnd(hosting)
        await settle(hosting)
        let ruleSwitches = descendants(hosting).compactMap { $0 as? NSSwitch }
        XCTAssertEqual(ruleSwitches.count, state.firewallRules.count)
        XCTAssertEqual(ruleSwitches.filter { $0.state == .on }.count,
                       state.firewallRules.filter { $0.stat.mode == "block" }.count)
        let lastSwitch = try XCTUnwrap(ruleSwitches.max { $0.convert($0.bounds, to: nil).minY > $1.convert($1.bounds, to: nil).minY })
        try assertVisible(lastSwitch, in: hosting)
        try snapshot(hosting, name: "minimum-firewall-end")

        // Notifications: one menu per flag type, default reads "Critical only".
        SettingsNavigation.shared.tab = .notifications
        await settle(hosting)
        let notifyMenus = menus(hosting)
        XCTAssertEqual(notifyMenus.count, SettingsView.notifyRules.count)
        XCTAssertTrue(notifyMenus.allSatisfy { $0.accessibilityValue() as? String == "Critical only" })
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "minimum-notifications")
        scrollDetailToEnd(hosting)
        await settle(hosting)
        assertOnScreen(try XCTUnwrap(menus(hosting).last), in: hosting, window: window)

        for tab: SettingsTab in [.exceptions, .providers, .chat, .traffic, .app, .updates] {
            SettingsNavigation.shared.tab = tab
            await settle(hosting)
            assertHorizontalFit(hosting, window: window)
            try snapshot(hosting, name: "minimum-\(tab)")
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

    /// Pop-up menus, top to bottom (SwiftUI menu pickers are pop-up button
    /// cells, not NSPopUpButton views).
    private func menus(_ view: NSView) -> [any NSAccessibilityProtocol] {
        nodes(view).filter { $0.accessibilityRole() == .popUpButton }
            .sorted { $0.accessibilityFrame().minY > $1.accessibilityFrame().minY }
    }

    private func sidebarTable(_ view: NSView) -> NSTableView? {
        descendants(view).compactMap { $0 as? NSTableView }.first {
            view.convert($0.bounds, from: $0).minX < 196
        }
    }

    /// An accessibility element (SwiftUI switches are not always NSViews)
    /// lies inside the detail scroll viewport and the window content.
    private func assertOnScreen(_ node: any NSAccessibilityProtocol, in view: NSView, window: NSWindow) {
        let frame = node.accessibilityFrame()
        XCTAssertGreaterThan(frame.width, 0, "Element has no on-screen frame")
        guard let scroll = detailScroll(view) else { return XCTFail("No detail scroll view") }
        let viewport = window.convertToScreen(scroll.convert(scroll.contentView.frame, to: nil))
        XCTAssertTrue(viewport.insetBy(dx: -1, dy: -1).contains(frame),
                      "Final control must be inside the visible detail scroll viewport")
    }

    private func assertVisible(_ control: NSView, in view: NSView) throws {
        let scroll = try XCTUnwrap(detailScroll(view))
        let frameInClip = scroll.contentView.convert(control.bounds, from: control)
        XCTAssertTrue(scroll.contentView.bounds.contains(frameInClip),
                      "Final control must be inside the visible detail scroll viewport")
        let frameInRoot = view.convert(control.bounds, from: control)
        XCTAssertTrue(view.bounds.contains(frameInRoot),
                      "Control must also be inside the actual window content")
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

    private func sendKey(_ character: String, keyCode: UInt16, window: NSWindow) throws {
        // Match a complete physical key press. Arrow keys carry the function
        // and numeric-pad flags; activation may occur when Space is released.
        let flags: NSEvent.ModifierFlags = (123...126).contains(keyCode) ? [.function, .numericPad] : []
        for type: NSEvent.EventType in [.keyDown, .keyUp] {
            let event = try XCTUnwrap(NSEvent.keyEvent(with: type, location: .zero,
                modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: window.windowNumber, context: nil, characters: character,
                charactersIgnoringModifiers: character, isARepeat: false, keyCode: keyCode))
            // Exercise NSApplication's event context, as the running app does.
            NSApp.postEvent(event, atStart: false)
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
