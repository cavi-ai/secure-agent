import AppKit
import Foundation
import UserNotifications

@MainActor
public final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var client: DaemonClient!
    private var isPaused = false

    private var currentStatus: StatusResponse?
    private var currentFlags: [FlagModel] = []
    private var currentIncidents: [IncidentReportModel] = []
    private var currentEvents: [EventModel] = []
    private var notifiedFlagIDs: Set<String> = []

    private var timer: Timer?

    public func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        // Self-heal any legacy KeepAlive LaunchAgent, then run the daemon as a
        // child of this app so it lives and dies with the visible menu bar icon.
        SetupManager.shared.migrateLegacyLaunchAgent()
        DaemonSupervisor.shared.start()

        client = DaemonClient()
        NotificationManager.shared.requestAuthorization()

        setupStatusItem()
        startPolling()

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
            let img = NSImage(systemSymbolName: "shield", accessibilityDescription: "secure-agent")
            img?.isTemplate = true
            button.image = img
            button.title = " 🛡️"
        }
        updateMenu()
    }

    private func startPolling() {
        fetchDaemonState()
        scheduleTimer(interval: 1.0)
    }

    private func scheduleTimer(interval: TimeInterval) {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.fetchDaemonState()
            }
        }
    }

    private func fetchDaemonState() {
        guard !isPaused else { return }

        Task {
            do {
                let status = try await client.fetchStatus()
                let flags = try await client.fetchFlags(limit: 20)
                let incidents = (try? await client.fetchIncidents(limit: 10)) ?? []
                let events = try await client.fetchEvents(limit: 50)

                await MainActor.run {
                    let wasDisconnected = self.currentStatus == nil
                    self.currentStatus = status
                    self.currentFlags = flags
                    self.currentIncidents = incidents
                    self.currentEvents = events
                    if wasDisconnected {
                        // Daemon is back: restore fast polling.
                        self.scheduleTimer(interval: 1.0)
                    }
                    self.processNewFlags(flags)
                    self.updateStatusIcon()
                    self.updateMenu()
                }
            } catch {
                await MainActor.run {
                    let wasConnected = self.currentStatus != nil
                    self.currentStatus = nil
                    self.currentIncidents = []
                    if wasConnected {
                        // Daemon went away: back off to reduce socket churn.
                        self.scheduleTimer(interval: 5.0)
                    }
                    self.updateStatusIcon()
                    self.updateMenu()
                }
            }
        }
    }

    private func processNewFlags(_ flags: [FlagModel]) {
        for flag in flags where flag.severity >= 2 {
            if !notifiedFlagIDs.contains(flag.id) {
                notifiedFlagIDs.insert(flag.id)
                NotificationManager.shared.sendNotification(for: flag)
            }
        }
    }

    private func updateStatusIcon() {
        guard let button = statusItem.button else { return }

        if !currentIncidents.isEmpty || currentFlags.contains(where: { $0.severity >= 3 }) {
            let img = NSImage(systemSymbolName: "exclamationmark.shield.fill", accessibilityDescription: "Flagged: Critical Security Alert")
            img?.isTemplate = true
            button.image = img
            button.title = " 🚨"
        } else if let status = currentStatus, status.activeAgents > 0 {
            let img = NSImage(systemSymbolName: "bolt.shield.fill", accessibilityDescription: "Agents Active")
            img?.isTemplate = true
            button.image = img
            button.title = " 🛡️ \(status.activeAgents)"
        } else {
            let img = NSImage(systemSymbolName: "shield", accessibilityDescription: "Quiet: Monitoring Active")
            img?.isTemplate = true
            button.image = img
            button.title = " 🛡️"
        }
    }

    private func updateMenu() {
        let menu = MenuBuilder.buildMenu(
            status: currentStatus,
            flags: currentFlags,
            incidents: currentIncidents,
            events: currentEvents,
            isPaused: isPaused,
            target: self,
            refreshAction: #selector(refreshClicked),
            killAction: #selector(killClicked(_:)),
            viewIncidentAction: #selector(viewIncidentClicked(_:)),
            pauseAction: #selector(pauseClicked),
            dashboardAction: #selector(dashboardClicked),
            setupAction: #selector(setupClicked),
            uninstallAction: #selector(uninstallClicked),
            quitAction: #selector(quitClicked)
        )
        statusItem.menu = menu
    }

    @objc private func refreshClicked() {
        fetchDaemonState()
    }

    @objc private func killClicked(_ sender: NSMenuItem) {
        let pid = Int32(sender.tag)
        guard pid > 0 else { return }

        Task {
            do {
                let success = try await client.killProcess(pid: pid)
                await MainActor.run {
                    if success {
                        print("[secure-agent-menubar] Killed process PID \(pid)")
                        self.fetchDaemonState()
                    } else {
                        print("[secure-agent-menubar] Failed to kill process PID \(pid)")
                    }
                }
            } catch {
                print("[secure-agent-menubar] Error killing process PID \(pid): \(error)")
            }
        }
    }

    @objc private func viewIncidentClicked(_ sender: NSMenuItem) {
        guard let incID = sender.representedObject as? String else { return }
        let matchingInc = currentIncidents.first(where: { $0.id == incID })

        Task {
            do {
                let md = try await client.fetchIncidentMarkdown(id: incID)
                await MainActor.run {
                    let alert = NSAlert()
                    alert.messageText = "Incident Containment & Remediation (\(incID))"
                    alert.informativeText = md.isEmpty ? "No detailed markdown available." : md
                    alert.addButton(withTitle: "⚡ Auto-Rotate Secrets")
                    alert.addButton(withTitle: "Copy Markdown")
                    alert.addButton(withTitle: "Close")
                    let response = alert.runModal()

                    if response == .alertFirstButtonReturn {
                        // Auto-Rotate Secrets clicked
                        if let inc = matchingInc {
                            Task {
                                var logResults: [String] = []
                                for item in inc.rotateList {
                                    do {
                                        let msg = try await self.client.executeRotation(incidentId: incID, itemId: item.id)
                                        logResults.append("✅ \(item.name): \(msg)")
                                    } catch {
                                        logResults.append("❌ \(item.name): \(error.localizedDescription)")
                                    }
                                }
                                await MainActor.run {
                                    let resAlert = NSAlert()
                                    resAlert.messageText = "Auto-Rotation Results"
                                    resAlert.informativeText = logResults.isEmpty ? "No items to rotate." : logResults.joined(separator: "\n\n")
                                    resAlert.addButton(withTitle: "OK")
                                    resAlert.runModal()
                                    self.fetchDaemonState()
                                }
                            }
                        }
                    } else if response == .alertSecondButtonReturn {
                        // Copy Markdown clicked
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(md, forType: .string)
                    }
                }
            } catch {
                print("[secure-agent-menubar] Error fetching incident markdown: \(error)")
            }
        }
    }

    @objc private func pauseClicked() {
        isPaused.toggle()
        updateMenu()
    }

    @objc private func dashboardClicked() {
        let port = currentStatus?.proxyPort ?? 8443
        if let url = URL(string: "http://localhost:\(port)/dashboard/") {
            NSWorkspace.shared.open(url)
        }
    }

    @objc private func setupClicked() {
        OnboardingWindowController.shared.show()
    }

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

    @objc private func quitClicked() {
        NSApp.terminate(nil)
    }
}
