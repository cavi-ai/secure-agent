import AppKit
import Foundation
import SwiftUI
import UserNotifications

@MainActor
public final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private let state = AppState()
    private let popover = NSPopover()

    public func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        // Self-heal any legacy KeepAlive LaunchAgent, then run the daemon as a
        // child of this app so it lives and dies with the visible menu bar icon.
        SetupManager.shared.migrateLegacyLaunchAgent()
        DaemonSupervisor.shared.start()
        NotificationManager.shared.requestAuthorization()

        setupStatusItem()
        setupPopover()
        state.onChange = { [weak self] in self?.updateStatusIcon() }
        state.start()

        Task {
            await SetupManager.shared.refreshState()
            if SetupManager.shared.needsSetup {
                OnboardingWindowController.shared.showOnceIfNeeded()
            }
        }
    }

    public func applicationWillTerminate(_ notification: Notification) {
        // Quitting the app must take the daemon with it — no hidden survivor.
        DaemonSupervisor.shared.stop()
    }

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            let img = NSImage(systemSymbolName: "shield", accessibilityDescription: "Secure Agent")
            img?.isTemplate = true
            button.image = img
            button.title = ""
            button.target = self
            button.action = #selector(statusItemClicked)
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
    }

    private func setupPopover() {
        popover.behavior = .transient
        popover.animates = true
        popover.contentViewController = NSHostingController(rootView: ConsoleView(state: state))
    }

    @objc private func statusItemClicked() {
        guard let button = statusItem.button else { return }
        if NSApp.currentEvent?.type == .rightMouseUp {
            showRightClickMenu(button)
        } else {
            togglePopover(button)
        }
    }

    private func togglePopover(_ button: NSStatusBarButton) {
        if popover.isShown {
            popover.performClose(nil)
        } else {
            state.refresh()
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    /// A small native menu on right-click: the quick actions that don't belong
    /// in the popover (Pause, Setup, Uninstall, Quit).
    private func showRightClickMenu(_ button: NSStatusBarButton) {
        let menu = NSMenu()
        func item(_ title: String, _ symbol: String, _ action: Selector, _ key: String = "") -> NSMenuItem {
            let it = NSMenuItem(title: title, action: action, keyEquivalent: key)
            it.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
            it.target = self
            return it
        }
        menu.addItem(item(state.isPaused ? "Resume monitoring" : "Pause monitoring",
                          state.isPaused ? "play.circle" : "pause.circle", #selector(pauseClicked)))
        menu.addItem(item("Setup & Permissions…", "gearshape", #selector(setupClicked)))
        menu.addItem(item("Uninstall…", "trash", #selector(uninstallClicked)))
        menu.addItem(.separator())
        menu.addItem(item("Quit Secure Agent", "power", #selector(quitClicked), "q"))

        statusItem.menu = menu
        button.performClick(nil)
        statusItem.menu = nil
    }

    private func updateStatusIcon() {
        guard let button = statusItem.button else { return }
        let name: String
        var count = ""
        if !state.incidents.isEmpty || state.flags.contains(where: { $0.severity >= 3 }) {
            name = "exclamationmark.shield.fill"
        } else if let s = state.status, s.activeAgents > 0 {
            name = "bolt.shield.fill"
            count = " \(s.activeAgents)"
        } else {
            name = "shield"
        }
        let img = NSImage(systemSymbolName: name, accessibilityDescription: "Secure Agent")
        img?.isTemplate = true
        button.image = img
        button.title = count
    }

    // MARK: - Right-click actions

    @objc private func pauseClicked() { state.togglePause() }

    @objc private func setupClicked() { OnboardingWindowController.shared.show() }

    @objc private func quitClicked() { NSApp.terminate(nil) }

    @objc private func uninstallClicked() {
        let alert = NSAlert()
        alert.messageText = "Uninstall Secure Agent?"
        alert.informativeText = "This stops the background daemon, removes harness hooks, the login item, and the CLI symlink. The app itself and your logs/config are left in place."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Uninstall")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        do {
            try SetupManager.shared.uninstallAll()
        } catch {
            SetupManager.shared.report(error)
        }
        Task { await SetupManager.shared.refreshState() }
        NSApp.terminate(nil)
    }
}
