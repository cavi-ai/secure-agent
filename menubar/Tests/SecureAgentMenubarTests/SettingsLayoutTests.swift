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
        if ProcessInfo.processInfo.environment["CI"] == "true" {
            XCTAssertTrue(NSApp.isFullKeyboardAccessEnabled,
                          "CI must enable AppKit keyboard navigation before launching the tests")
        }
        NSApp.finishLaunching()
        let priorTab = SettingsNavigation.shared.tab
        SettingsNavigation.shared.tab = .protection
        let state = AppState.preview()
        #if DEBUG
        state.seedForTesting(status: StatusResponse(
            running: true, uptime: "test fixture", activeAgents: 0,
            firewallStats: Dictionary(uniqueKeysWithValues: (0..<16).map {
                (String(format: "fixture-rule-%02d", $0), RuleStatModel(
                    wouldBlock: $0, blocked: 0, legit: 1, mode: "monitor"))
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
        try assertControl("Files", in: hosting)
        try assertControl("Network", in: hosting)
        let fileControls = segmentedControls(hosting, containing: "Deny")
        XCTAssertEqual(fileControls.count, 6)
        try assertVisible(try XCTUnwrap(fileControls.last), in: hosting)
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "minimum-files")

        let protectionControl = try XCTUnwrap(segmentedControls(hosting, containing: "Files").first)
        try keyboardMove(protectionControl, keyCode: 124, character: "\u{F703}", window: window)
        XCTAssertEqual(protectionControl.selectedSegment, 1)
        await settle(hosting)
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "minimum-network-top")
        scrollDetailToEnd(hosting)
        await settle(hosting)
        let networkControls = segmentedControls(hosting, containing: "Block")
        XCTAssertEqual(networkControls.count, state.firewallRules.count)
        try assertVisible(try XCTUnwrap(networkControls.last), in: hosting)
        try snapshot(hosting, name: "minimum-network-end")

        SettingsNavigation.shared.tab = .secureAgent
        await settle(hosting)
        try press("Analysis", in: hosting)
        await settle(hosting)
        assertHorizontalFit(hosting, window: window)
        try snapshot(hosting, name: "minimum-analysis-top")
        scrollDetailToEnd(hosting)
        await settle(hosting)
        try snapshot(hosting, name: "minimum-analysis-end")

        var aiControl = try XCTUnwrap(segmentedControls(hosting, containing: "Analysis").first)
        try keyboardMove(aiControl, keyCode: 124, character: "\u{F703}", window: window)
        await settle(hosting)
        XCTAssertEqual(aiControl.selectedSegment, 2, "Right arrow and Space must select Traffic")
        try snapshot(hosting, name: "minimum-traffic-keyboard")
        SettingsNavigation.shared.tab = .protection
        await settle(hosting)
        SettingsNavigation.shared.tab = .secureAgent
        await settle(hosting)
        aiControl = try XCTUnwrap(segmentedControls(hosting, containing: "Analysis").first)
        XCTAssertEqual(aiControl.selectedSegment, 2,
                       "Local destination selection must survive sidebar navigation")
        try keyboardMove(aiControl, keyCode: 123, character: "\u{F702}", window: window)
        await settle(hosting)
        XCTAssertEqual(aiControl.selectedSegment, 1, "Left arrow and Space must return to Analysis")

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

    private func element(_ label: String, in view: NSView) -> (any NSAccessibilityProtocol)? {
        nodes(view).first { $0.accessibilityLabel() == label || $0.accessibilityTitle() == label }
    }

    private func assertControl(_ label: String, in view: NSView) throws {
        _ = try XCTUnwrap(element(label, in: view), "Missing native accessibility control: " + label)
    }

    private func press(_ label: String, in view: NSView) throws {
        if element(label, in: view)?.accessibilityPerformPress() == true { return }
        if let control = descendants(view).compactMap({ $0 as? NSSegmentedControl }).first(where: { control in
            (0..<control.segmentCount).contains { control.label(forSegment: $0) == label }
        }), let index = (0..<control.segmentCount).first(where: { control.label(forSegment: $0) == label }) {
            control.selectedSegment = index
            XCTAssertTrue(control.sendAction(control.action, to: control.target), label)
            return
        }
        XCTFail("Native local segmented control unavailable: " + label)
    }

    private func descendants(_ view: NSView) -> [NSView] {
        [view] + view.subviews.flatMap(descendants)
    }

    private func detailScroll(_ view: NSView) -> NSScrollView? {
        descendants(view).compactMap { $0 as? NSScrollView }.first {
            view.convert($0.bounds, from: $0).minX >= 196
        }
    }

    private func segmentedControls(_ view: NSView, containing label: String) -> [NSSegmentedControl] {
        descendants(view).compactMap { $0 as? NSSegmentedControl }.filter { control in
            (0..<control.segmentCount).contains { control.label(forSegment: $0) == label }
        }
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

    private func keyboardMove(_ control: NSSegmentedControl, keyCode: UInt16,
                              character: String, window: NSWindow) throws {
        XCTAssertTrue(window.makeFirstResponder(control))
        XCTAssertTrue(window.firstResponder === control)
        let expected = (control.selectedSegment + (keyCode == 124 ? 1 : control.segmentCount - 1)) % control.segmentCount
        try sendKey(character, keyCode: keyCode, window: window)
        try sendKey(" ", keyCode: 49, window: window)
        drainApplicationEvents()
        XCTAssertEqual(control.selectedSegment, expected,
                       "Native key press must select the adjacent segment; keyWindow=\(window.isKeyWindow), fullKeyboardAccess=\(NSApp.isFullKeyboardAccessEnabled)")
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
        let flags: NSEvent.ModifierFlags = [123, 124].contains(keyCode) ? [.function, .numericPad] : []
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
