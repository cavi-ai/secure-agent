import AppKit
import Foundation
import SwiftUI
import UserNotifications

@MainActor
public final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private var statusItem: NSStatusItem!
    private let state = AppState()
    private let popover = NSPopover()
    private var launchTask: Task<Void, Never>?
    /// A repair URL that arrives before launch finishes waits for it.
    private var launched = false
    private var telemetryRepairRequested = false

    public func applicationDidFinishLaunching(_ notification: Notification) {
        // The Dock is the durable fallback control when macOS hides a status
        // item. Monitoring must never depend on an unobservable AX frame.
        NSApp.setActivationPolicy(.regular)

        // Put a usable menu bar control on screen before setup or daemon work.
        guard setupStatusItem() else {
            let alert = NSAlert()
            alert.messageText = "Secure Agent could not appear in the menu bar"
            alert.informativeText = "Monitoring was not started. Quit another copy or free menu bar space, then reopen Secure Agent."
            alert.addButton(withTitle: "OK")
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
            NSApp.terminate(nil)
            return
        }
        setupPopover()
        SettingsWindowController.shared.appState = state
        launchTask = Task { [weak self] in
            guard let self else { return }
            guard await AppInstanceGuard.shared.claimOrExplain() else {
                if !Task.isCancelled { NSApp.terminate(nil) }
                return
            }
            guard !Task.isCancelled else { return }
            SettingsWindowController.shared.show()
            finishLaunching()
        }
    }

    public func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        // A status bar button may count as a visible window here; Dock clicks
        // should still restore the Settings control surface after it closes.
        SettingsWindowController.shared.show()
        return true
    }

    private func finishLaunching() {
        // Self-heal any legacy KeepAlive LaunchAgent, then run the daemon as a
        // child of this app so it lives and dies with the visible menu bar icon.
        SetupManager.shared.migrateLegacyLaunchAgent()
        SetupManager.shared.refreshInstalledHooks()
        DaemonSupervisor.shared.start()
        NotificationManager.shared.requestAuthorization()
        UNUserNotificationCenter.current().delegate = self
        // File telemetry turns itself on: register once per launch, then open
        // the pane for each switch the user has to flip.
        SetupManager.shared.refreshESState()
        launched = true
        if telemetryRepairRequested {
            telemetryRepairRequested = false
            SetupManager.shared.reregisterESService()
        }

        state.onChange = { [weak self] in self?.updateStatusIcon() }
        state.onNewCriticalFlag = { [weak self] in self?.flashStatusBadge() }
        state.start()

        Task {
            await SetupManager.shared.reapplyClaudeRouting()
        }
        Task {
            await SetupManager.shared.refreshState()
            if SetupManager.shared.needsSetup {
                OnboardingWindowController.shared.showOnceIfNeeded()
            }
        }
    }

    /// `secure-agent://telemetry/repair`, from `secure-agent telemetry repair`:
    /// re-register the file-telemetry helper now.
    public func application(_ application: NSApplication, open urls: [URL]) {
        guard urls.contains(where: ESAutopilot.isRepairURL) else { return }
        if launched {
            SetupManager.shared.reregisterESService()
        } else {
            telemetryRepairRequested = true
        }
    }

    public func applicationWillTerminate(_ notification: Notification) {
        // Quitting the app must take the daemon with it — no hidden survivor.
        // Stop the event stream/polling first so no in-flight fetch outlives us.
        launchTask?.cancel()
        state.stop()
        // Routing points Claude Code at this app's proxy; take it back before
        // the proxy goes away.
        SetupManager.shared.withdrawClaudeRouting()
        DaemonSupervisor.shared.stop()
        AppInstanceGuard.shared.release()
    }

    /// The console's `--brand` purple (style.css): hsl(248 92% 70%) on a dark
    /// menu bar, hsl(248 62% 52%) on a light one.
    static let statusTint = NSColor(name: "SecureAgentBrand") { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(srgbRed: 0.498, green: 0.424, blue: 0.976, alpha: 1)
            : NSColor(srgbRed: 0.302, green: 0.222, blue: 0.818, alpha: 1)
    }

    private func setupStatusItem() -> Bool {
        guard let item = makeStatusItem() else { return false }
        statusItem = item
        return true
    }

    /// Kept separate from daemon startup so launch visibility can be tested.
    func makeStatusItem() -> NSStatusItem? {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        guard let button = item.button,
              let icon = Self.statusIcon("checkmark.shield.fill") else {
            NSStatusBar.system.removeStatusItem(item)
            return nil
        }
        button.image = icon
        button.title = ""
        button.target = self
        button.action = #selector(statusItemClicked)
        button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        return item
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
        menu.addItem(item(state.isPaused ? "Resume alerts" : "Pause alerts",
                          state.isPaused ? "play.circle" : "pause.circle", #selector(pauseClicked)))
        menu.addItem(item("Settings…", "gearshape.2", #selector(settingsClicked), ","))
        menu.addItem(item("Setup & Permissions…", "gearshape", #selector(setupClicked)))
        menu.addItem(item("Run Doctor…", "stethoscope", #selector(doctorClicked)))
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
        let foreground: NSColor
        let detail: NSColor
        var count = ""
        if state.isPaused {
            name = "pause.shield.fill"
            foreground = .systemGray
            detail = .white
        } else if state.needsAttention {
            // /posture state: the same verdict the hero and console use.
            // Previously this counted raw flags and
            // incidents, so an acknowledged flag or resolved incident kept the
            // warning lit forever — the "always there no matter what" report.
            name = "exclamationmark.shield.fill"
            foreground = .systemYellow
            detail = .black
        } else if let s = state.status, s.activeAgents > 0 {
            name = "checkmark.shield.fill"
            foreground = Self.statusTint
            detail = .white
            count = " \(s.activeAgents)"
        } else {
            name = "checkmark.shield.fill"
            foreground = Self.statusTint
            detail = .white
        }
        button.image = Self.statusIcon(name, foreground: foreground, detail: detail)
        button.attributedTitle = NSAttributedString(string: count, attributes: [.foregroundColor: Self.statusTint])
    }

    static func statusIcon(
        _ name: String,
        foreground: NSColor = statusTint,
        detail: NSColor = .white
    ) -> NSImage? {
        // A status bar may render an SF Symbol as a monochrome template even
        // after isTemplate is cleared. Supply actual RGBA pixels instead.
        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: 36, pixelsHigh: 36,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
            isPlanar: false, colorSpaceName: .deviceRGB,
            bytesPerRow: 0, bitsPerPixel: 0
        ), let context = NSGraphicsContext(bitmapImageRep: bitmap) else { return nil }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        let scale = NSAffineTransform()
        scale.scale(by: 2)
        scale.concat()
        foreground.setFill()
        let shield = NSBezierPath()
        shield.move(to: NSPoint(x: 9, y: 16.6))
        shield.curve(to: NSPoint(x: 16.2, y: 13.8), controlPoint1: NSPoint(x: 11.2, y: 16.6), controlPoint2: NSPoint(x: 14.4, y: 15.7))
        shield.line(to: NSPoint(x: 16.2, y: 8.5))
        shield.curve(to: NSPoint(x: 9, y: 1.2), controlPoint1: NSPoint(x: 16.2, y: 5.3), controlPoint2: NSPoint(x: 12.6, y: 2.4))
        shield.curve(to: NSPoint(x: 1.8, y: 8.5), controlPoint1: NSPoint(x: 5.4, y: 2.4), controlPoint2: NSPoint(x: 1.8, y: 5.3))
        shield.line(to: NSPoint(x: 1.8, y: 13.8))
        shield.curve(to: NSPoint(x: 9, y: 16.6), controlPoint1: NSPoint(x: 3.6, y: 15.7), controlPoint2: NSPoint(x: 6.8, y: 16.6))
        shield.close()
        shield.fill()
        detail.setStroke()
        let mark = NSBezierPath()
        mark.lineWidth = 2.1
        mark.lineCapStyle = .round
        mark.lineJoinStyle = .round
        if name == "pause.shield.fill" {
            for x in [7.0, 11.0] {
                mark.move(to: NSPoint(x: x, y: 6.8))
                mark.line(to: NSPoint(x: x, y: 11.4))
            }
        } else if name == "exclamationmark.shield.fill" {
            mark.move(to: NSPoint(x: 9, y: 7.9))
            mark.line(to: NSPoint(x: 9, y: 11.9))
        } else {
            mark.move(to: NSPoint(x: 5.4, y: 8.8))
            mark.line(to: NSPoint(x: 7.8, y: 6.4))
            mark.line(to: NSPoint(x: 12.7, y: 11.2))
        }
        mark.stroke()
        if name == "exclamationmark.shield.fill" {
            detail.setFill()
            NSBezierPath(ovalIn: NSRect(x: 8, y: 5.1, width: 2, height: 2)).fill()
        }
        context.flushGraphics()
        NSGraphicsContext.restoreGraphicsState()
        let image = NSImage(size: NSSize(width: 18, height: 18))
        image.addRepresentation(bitmap)
        image.isTemplate = false
        return image
    }

    // MARK: - Critical-flag badge pulse

    private var flashTask: Task<Void, Never>?

    /// Briefly alternate the status-item title between "!" and nothing, then
    /// restore the steady-state icon. A critical flag means a secret may have
    /// just left the machine — the menu bar must pull the eye even with the
    /// popover closed, without a permanent angry badge.
    private func flashStatusBadge() {
        flashTask?.cancel()
        flashTask = Task { @MainActor [weak self] in
            guard let self else { return }
            for i in 0..<6 {
                if Task.isCancelled { break }
                self.statusItem?.button?.title = (i % 2 == 0) ? " !" : ""
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
            self.updateStatusIcon()
        }
    }

    // MARK: - Notifications

    public nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }

    public nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let action = response.actionIdentifier
        let pid = (response.notification.request.content.userInfo["pid"] as? Int).map { Int32($0) }
        Task { @MainActor in
            switch action {
            case NotificationManager.killAction:
                if let pid { self.state.kill(pid: pid) }
            case NotificationManager.openAction, UNNotificationDefaultActionIdentifier:
                self.state.openDashboard()
            default:
                break
            }
        }
        completionHandler()
    }

    // MARK: - Right-click actions

    @objc private func pauseClicked() { state.togglePause() }

    @objc private func settingsClicked() { SettingsWindowController.shared.show() }

    @objc private func setupClicked() { OnboardingWindowController.shared.show() }

    @objc private func doctorClicked() {
        SettingsWindowController.shared.show(tab: .telemetry)
        Task { await SetupManager.shared.runDoctor() }
    }

    @objc private func quitClicked() { NSApp.terminate(nil) }

    @objc private func uninstallClicked() {
        SetupManager.shared.confirmUninstall()
        NSApp.terminate(nil)
    }
}
