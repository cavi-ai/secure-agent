import SwiftUI
import XCTest

@testable import SecureAgentMenubar

final class SnapshotTests: XCTestCase {
    /// Regression guard: the popover renders to a non-empty image from populated
    /// state (catches layout/type regressions in ConsoleView without a daemon).
    /// The preview includes a pending guard decision, so this also exercises the
    /// inline consent card.
    @MainActor
    func testConsoleViewRenders() throws {
        let renderer = ImageRenderer(content: ConsoleView(state: .preview(), scrollable: false))
        renderer.scale = 2.0
        let img = try XCTUnwrap(renderer.nsImage)
        XCTAssertGreaterThan(img.size.width, 0)
        XCTAssertGreaterThan(img.size.height, 0)
    }

    @MainActor
    func testUrgentEvidenceRendersWithoutFlagDetails() async throws {
        _ = NSApplication.shared
        let priorPolicy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        NSApp.activate(ignoringOtherApps: true)
        defer { NSApp.setActivationPolicy(priorPolicy) }
        for (name, basis, risk, control, residual, reason) in [
            ("unknown", "", "unknown", "unknown", "unknown", "Exposure and control outcome are unknown."),
            ("model-visible", "model-visible-read", "critical", "unknown", "model-exposure", "A sensitive file became model-visible."),
            ("observed-only", "fingerprint-payload", "critical", "observed-only", "transmission-attempt", "The local proxy observed this request without blocking it."),
            ("blocked", "fingerprint-payload", "critical", "blocked", "transmission-attempt", "The proxy rejected this request before forwarding.")
        ] {
            let raw = #"{"state":"critical","needs_you":1,"summary":"\#(reason)","connected":true,"items":[{"kind":"review","id":"finding","title":"Recorded finding","severity":3,"assessment":{"evidence_basis":["\#(basis)"],"risk":"\#(risk)","control":"\#(control)","residual_risk":"\#(residual)","review_state":"unreviewed","reason":"\#(reason)","limits":["Earlier exposure and external credential revocation are not verified."]}}]}"#
            let state = AppState.previewFlags([])
            state.seedPostureForTesting(try JSONDecoder().decode(PostureModel.self, from: Data(raw.utf8)))
            let view = ConsoleView(state: state, scrollable: false)
            XCTAssertEqual(view.heroModel.subtitle, reason)
            XCTAssertEqual(view.heroModel.buttonLabel, "Open in console")
            let controller = NSHostingController(rootView: view)
            let window = NSWindow(contentViewController: controller)
            window.isReleasedWhenClosed = false
            window.title = "Finding review"
            let size = controller.view.fittingSize
            window.setContentSize(NSSize(width: 340, height: size.height))
            window.makeKeyAndOrderFront(nil)
            defer { window.orderOut(nil); window.close() }
            try await Task.sleep(for: .milliseconds(200))
            controller.view.layoutSubtreeIfNeeded()
            XCTAssertEqual(controller.view.bounds.width, 340)
            XCTAssertGreaterThan(controller.view.bounds.height, 100)
            if let path = ProcessInfo.processInfo.environment["SECURE_AGENT_REVIEW_SCREENSHOTS"] {
                let dir = URL(fileURLWithPath: path)
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                let bitmap = try XCTUnwrap(controller.view.bitmapImageRepForCachingDisplay(in: controller.view.bounds))
                controller.view.cacheDisplay(in: controller.view.bounds, to: bitmap)
                try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
                    .write(to: dir.appendingPathComponent(name + ".png"))
                if CGPreflightScreenCaptureAccess() {
                    let capture = Process()
                    capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                    capture.arguments = ["-x", "-o", "-l", String(window.windowNumber), dir.appendingPathComponent(name + "-window.png").path]
                    try capture.run()
                    capture.waitUntilExit()
                    XCTAssertEqual(capture.terminationStatus, 0)
                }
            }
        }
    }

    /// The reduced popover must not lose the consent path: a pending guard
    /// surfaces the inline decision card with the plain-language headline.
    @MainActor
    func testPendingGuardHeadlineLanguage() {
        let p = GuardPending(id: "g1", agent: "claude", tool: "Read",
                             path: "/Users/x/.aws/credentials", ruleID: "cloud-creds",
                             ts: "", scopeText: nil, advisor: nil)
        XCTAssertEqual(ConsoleView.guardPromptHeadline(p),
                       "Claude wants to read a cloud credential file")
        XCTAssertTrue(ConsoleView.guardPromptDetail(p).contains("credentials"))
    }

    @MainActor
    func testPopoverReductionKeepsGuardVisible() {
        // The preview carries a pendingGuard — its presence is what the inline
        // card keys on. (A nil guard hides the card; nil is the all-clear case.)
        XCTAssertNotNil(AppState.preview().pendingGuard)
    }
}
