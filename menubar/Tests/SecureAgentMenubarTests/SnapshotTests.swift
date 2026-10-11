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

    /// Action feedback remains renderable after its finding leaves the queue.
    @MainActor
    func testActionResultsRenderAfterQueueRefresh() async throws {
        _ = NSApplication.shared
        let priorPolicy = NSApp.activationPolicy()
        XCTAssertTrue(NSApp.setActivationPolicy(.regular))
        NSApp.finishLaunching()
        NSApp.activate(ignoringOtherApps: true)
        defer { NSApp.setActivationPolicy(priorPolicy) }
        let raw = #"{"id":"action-finding","rule":"sensitive-read-then-connect","severity":3,"ts":"","pid":901,"agent":"cursor","session_id":"action-session","evidence":[],"title":"Sensitive file became model-visible","explain":{"what":"A model-visible file read","disposition":{"state":"critical","text":"Urgent review","why":""},"actions":[],"assessment":{"evidence_basis":["model-visible-read"],"risk":"critical","control":"unknown","residual_risk":"model-exposure","review_state":"unreviewed","reason":"A sensitive file became model-visible.","limits":["Delivery is not established."]}}}"#
        let flag = try JSONDecoder().decode(FlagModel.self, from: Data(raw.utf8))
        let action = FlagExplainAction(id: "allow-host", label: "Allow api.example.com for cursor",
            consequence: "Mark future traffic to this host as expected.", method: "POST", path: "/allowlist",
            body: ["agent": .string("cursor"), "host": .string("api.example.com")])
        for (name, heading) in [("applied", "Action applied"), ("partial", "Action applied; review unconfirmed"), ("failed", "Action not confirmed")] {
            let stub = StubDaemonClient()
            stub.flags = [flag]
            if name == "partial" { stub.acknowledgeError = DaemonClientError.transport("connection lost") }
            if name == "failed" { stub.performError = DaemonClientError.http(503) }
            if name != "applied" {
                stub.posture = PostureModel(state: "critical", needsYou: 1,
                    summary: "A sensitive file became model-visible.", connected: true)
            }
            let state = AppState(client: stub)
            state.seedForTesting(status: stub.status)
            state.seedFlagsForTesting([flag])
            await state.performInPlace(action, on: flag)
            let view = ConsoleView(state: state, scrollable: false)
            XCTAssertEqual(view.actionResultModel?.heading, heading)
            if name == "applied" { XCTAssertNil(view.heroModel.flag) }
            let controller = NSHostingController(rootView: view)
            let window = NSWindow(contentViewController: controller)
            window.isReleasedWhenClosed = false
            window.title = "Finding action result"
            window.setContentSize(NSSize(width: 340, height: controller.view.fittingSize.height))
            window.makeKeyAndOrderFront(nil)
            defer { window.orderOut(nil); window.close() }
            try await Task.sleep(for: .milliseconds(200))
            controller.view.layoutSubtreeIfNeeded()
            XCTAssertEqual(controller.view.bounds.width, 340)
            XCTAssertGreaterThan(controller.view.bounds.height, 100)
            if let path = ProcessInfo.processInfo.environment["SECURE_AGENT_ACTION_SCREENSHOTS"], CGPreflightScreenCaptureAccess() {
                let dir = URL(fileURLWithPath: path)
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                let capture = Process()
                capture.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
                capture.arguments = ["-x", "-o", "-l", String(window.windowNumber), dir.appendingPathComponent(name + ".png").path]
                try capture.run()
                capture.waitUntilExit()
                XCTAssertEqual(capture.terminationStatus, 0)
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
