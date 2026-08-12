import AppKit

public final class MenuBuilder: @unchecked Sendable {
    public static func buildMenu(
        status: StatusResponse?,
        flags: [FlagModel],
        events: [EventModel],
        isPaused: Bool,
        target: AnyObject,
        refreshAction: Selector,
        killAction: Selector,
        pauseAction: Selector,
        quitAction: Selector
    ) -> NSMenu {
        let menu = NSMenu()

        // 1. Status Header
        let statusItem: NSMenuItem
        if let s = status, s.running {
            statusItem = NSMenuItem(title: "secure-agentd: Active (Uptime: \(s.uptime))", action: nil, keyEquivalent: "")
            statusItem.image = NSImage(systemSymbolName: "checkmark.circle.fill", accessibilityDescription: "Connected")?
                .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 12, weight: .regular))
        } else {
            statusItem = NSMenuItem(title: "secure-agentd: Disconnected", action: nil, keyEquivalent: "")
            statusItem.image = NSImage(systemSymbolName: "xmark.circle.fill", accessibilityDescription: "Disconnected")
        }
        statusItem.isEnabled = false
        menu.addItem(statusItem)

        menu.addItem(NSMenuItem.separator())

        // 2. Security Flags Section
        if !flags.isEmpty {
            let flagsHeader = NSMenuItem(title: "SECURITY ALERTS (\(flags.count))", action: nil, keyEquivalent: "")
            flagsHeader.isEnabled = false
            menu.addItem(flagsHeader)

            for flag in flags {
                let sevPrefix = flag.severity >= 3 ? "🔴 [CRITICAL]" : "🟡 [WARN]"
                let flagItem = NSMenuItem(title: "\(sevPrefix) \(flag.rule) — \(flag.agent) (PID \(flag.pid))", action: nil, keyEquivalent: "")
                flagItem.isEnabled = false
                menu.addItem(flagItem)

                for ev in flag.evidence {
                    let evItem = NSMenuItem(title: "   ↳ \(ev)", action: nil, keyEquivalent: "")
                    evItem.isEnabled = false
                    menu.addItem(evItem)
                }

                // Kill process item for this flag
                let killItem = NSMenuItem(title: "   ⚡ Kill \(flag.agent) Process (PID \(flag.pid))", action: killAction, keyEquivalent: "")
                killItem.target = target
                killItem.tag = Int(flag.pid)
                menu.addItem(killItem)
            }

            menu.addItem(NSMenuItem.separator())
        }

        // 3. Active Agents Summary
        let activeCount = status?.activeAgents ?? 0
        let agentsHeader = NSMenuItem(title: "ACTIVE AGENTS (\(activeCount))", action: nil, keyEquivalent: "")
        agentsHeader.isEnabled = false
        menu.addItem(agentsHeader)

        if activeCount == 0 {
            let noneItem = NSMenuItem(title: "No active agent processes detected", action: nil, keyEquivalent: "")
            noneItem.isEnabled = false
            menu.addItem(noneItem)
        } else {
            // Group events by tagged PID
            var agentPIDs = Set<Int32>()
            for ev in events {
                if ev.kind == 8 /* KindPluginAction */ || ev.kind == 0 /* KindFileOpen */ {
                    agentPIDs.insert(ev.pid)
                }
            }
            for pid in agentPIDs {
                let item = NSMenuItem(title: "• Agent PID \(pid)", action: nil, keyEquivalent: "")
                item.isEnabled = false
                menu.addItem(item)

                let killItem = NSMenuItem(title: "   ⚡ Kill PID \(pid)", action: killAction, keyEquivalent: "")
                killItem.target = target
                killItem.tag = Int(pid)
                menu.addItem(killItem)
            }
        }

        menu.addItem(NSMenuItem.separator())

        // 4. Controls & System Actions
        let pauseTitle = isPaused ? "Resume Monitoring" : "Pause Monitoring"
        let pauseItem = NSMenuItem(title: pauseTitle, action: pauseAction, keyEquivalent: "")
        pauseItem.target = target
        menu.addItem(pauseItem)

        let refreshItem = NSMenuItem(title: "Refresh Now", action: refreshAction, keyEquivalent: "r")
        refreshItem.target = target
        menu.addItem(refreshItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit secure-agent-menubar", action: quitAction, keyEquivalent: "q")
        quitItem.target = target
        menu.addItem(quitItem)

        return menu
    }
}
