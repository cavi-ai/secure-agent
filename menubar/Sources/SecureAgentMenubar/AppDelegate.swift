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

        client = DaemonClient()
        NotificationManager.shared.requestAuthorization()

        setupStatusItem()
        startPolling()
    }

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield", accessibilityDescription: "secure-agent")
            button.target = self
            button.action = #selector(statusItemClicked)
        }
        updateMenu()
    }

    @objc private func statusItemClicked() {
        updateMenu()
        statusItem.button?.performClick(nil)
    }

    private func startPolling() {
        fetchDaemonState()
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
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
                    self.currentStatus = status
                    self.currentFlags = flags
                    self.currentIncidents = incidents
                    self.currentEvents = events
                    self.processNewFlags(flags)
                    self.updateStatusIcon()
                    self.updateMenu()
                }
            } catch {
                await MainActor.run {
                    self.currentStatus = nil
                    self.currentIncidents = []
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
            button.image = NSImage(systemSymbolName: "exclamationmark.shield.fill", accessibilityDescription: "Flagged: Critical Security Alert")
            button.title = " 🚨"
        } else if let status = currentStatus, status.activeAgents > 0 {
            button.image = NSImage(systemSymbolName: "bolt.shield.fill", accessibilityDescription: "Agents Active")
            button.title = " \(status.activeAgents)"
        } else {
            button.image = NSImage(systemSymbolName: "shield", accessibilityDescription: "Quiet: Monitoring Active")
            button.title = ""
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

        Task {
            do {
                let md = try await client.fetchIncidentMarkdown(id: incID)
                await MainActor.run {
                    let alert = NSAlert()
                    alert.messageText = "Incident Containment Report (\(incID))"
                    alert.informativeText = md.isEmpty ? "No detailed markdown available." : md
                    alert.addButton(withTitle: "Copy Markdown")
                    alert.addButton(withTitle: "Close")
                    let response = alert.runModal()
                    if response == .alertFirstButtonReturn {
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

    @objc private func quitClicked() {
        NSApp.terminate(nil)
    }
}
