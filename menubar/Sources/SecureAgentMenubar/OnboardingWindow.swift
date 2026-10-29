import AppKit
import SwiftUI

/// First-use setup for one selected agent path.
@MainActor
public final class OnboardingWindowController: NSObject, NSWindowDelegate {
    public static let shared = OnboardingWindowController()

    private var window: NSWindow?
    private(set) var flow: FirstUseSetupFlow?
    private let setup: SetupManager
    private let preferences: UserDefaults
    public var appState: AppState?

    init(setup: SetupManager = .shared, preferences: UserDefaults = AppPreferences.shared) {
        self.setup = setup
        self.preferences = preferences
        super.init()
    }

    public func show() { show(harness: nil) }

    func show(harness: String?) {
        guard let appState else { return }
        if let window {
            if let harness, !setup.hookSetupRunning, !setup.hookSelfTestRunning {
                flow?.beginSetup(for: harness)
            }
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let flow = FirstUseSetupFlow(selectedHarness: harness)
        if let harness { flow.beginSetup(for: harness) }
        self.flow = flow
        let view = OnboardingView(setup: setup, appState: appState, flow: flow, onDone: { [weak self] in self?.close() })
        let hosting = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: hosting)
        window.title = "Secure Agent Setup"
        window.appearance = NSAppearance(named: .darkAqua)
        window.styleMask = [.titled, .closable, .resizable]
        window.setContentSize(NSSize(width: 560, height: 650))
        window.contentMinSize = NSSize(width: 520, height: 580)
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self
        self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Auto-show the wizard at most once; afterwards it's only reachable
    /// via the "Setup & Permissions…" menu item.
    public func showOnceIfNeeded() {
        guard !preferences.bool(forKey: "setupWizardDismissed") else { return }
        show()
    }

    public func close() {
        preferences.set(true, forKey: "setupWizardDismissed")
        window?.close()
        window = nil
        flow = nil
    }

    public func windowWillClose(_ notification: Notification) {
        preferences.set(true, forKey: "setupWizardDismissed")
        window = nil
        flow = nil
    }
}
