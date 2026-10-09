import AppKit
import SwiftUI

/// First-use setup for one selected agent path.
@MainActor
public final class OnboardingWindowController: NSObject, NSWindowDelegate {
    public static let shared = OnboardingWindowController()

    private var window: NSWindow?

    public func show() {
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let view = OnboardingView(onDone: { [weak self] in self?.close() })
        let hosting = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: hosting)
        window.title = "Secure Agent Setup"
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
        guard !AppPreferences.shared.bool(forKey: "setupWizardDismissed") else { return }
        show()
    }

    public func close() {
        AppPreferences.shared.set(true, forKey: "setupWizardDismissed")
        window?.close()
        window = nil
    }

    public func windowWillClose(_ notification: Notification) {
        AppPreferences.shared.set(true, forKey: "setupWizardDismissed")
        window = nil
    }
}
