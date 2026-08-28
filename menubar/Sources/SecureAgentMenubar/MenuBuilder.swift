import AppKit

public final class MenuBuilder: @unchecked Sendable {
    public static func buildMenu(
        status: StatusResponse?,
        flags: [FlagModel],
        incidents: [IncidentReportModel],
        events: [EventModel],
        isPaused: Bool,
        target: AnyObject,
        refreshAction: Selector,
        killAction: Selector,
        viewIncidentAction: Selector,
        pauseAction: Selector,
        dashboardAction: Selector,
        setupAction: Selector,
        uninstallAction: Selector,
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

        if let s = status, s.proxyEnabled == true, let port = s.proxyPort {
            let proxyItem = NSMenuItem(title: "Opt-in Proxy: Active (127.0.0.1:\(port))", action: nil, keyEquivalent: "")
            proxyItem.image = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: "Proxy Active")
            proxyItem.isEnabled = false
            menu.addItem(proxyItem)
        }

        if let s = status, let fw = s.firewallStats, !fw.isEmpty {
            let wouldBlock = fw.values.reduce(0) { $0 + $1.wouldBlock }
            let blocked = fw.values.reduce(0) { $0 + $1.blocked }
            let fwItem = NSMenuItem(title: "Egress Firewall: \(wouldBlock) would-block · \(blocked) blocked", action: nil, keyEquivalent: "")
            fwItem.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Egress Firewall")
            fwItem.isEnabled = false
            menu.addItem(fwItem)
        }

        if let s = status, let uninspected = s.uninspectedEgress, uninspected > 0 {
            let uItem = NSMenuItem(title: "Uninspected egress: \(uninspected) endpoint\(uninspected == 1 ? "" : "s")", action: nil, keyEquivalent: "")
            uItem.image = NSImage(systemSymbolName: "eye.trianglebadge.exclamationmark", accessibilityDescription: "Uninspected egress")
            uItem.isEnabled = false
            menu.addItem(uItem)
        }

        menu.addItem(NSMenuItem.separator())

        // 2. Incident Containment & Rotation Section
        if !incidents.isEmpty {
            let incHeader = NSMenuItem(title: "INCIDENT CONTAINMENT & ROTATION (\(incidents.count))", action: nil, keyEquivalent: "")
            incHeader.isEnabled = false
            menu.addItem(incHeader)

            for (idx, inc) in incidents.prefix(5).enumerated() {
                let riskPrefix = inc.risk == "CRITICAL" ? "🚨 [CRITICAL]" : "⚠️ [HIGH]"
                let incItem = NSMenuItem(title: "\(riskPrefix) \(inc.rule) — PID \(inc.pid) (\(inc.rotateList.count) Rotate Items)", action: nil, keyEquivalent: "")
                incItem.isEnabled = false
                menu.addItem(incItem)

                for item in inc.rotateList {
                    let rotItem = NSMenuItem(title: "   🔑 Rotate: \(item.name) (\(item.category))", action: nil, keyEquivalent: "")
                    rotItem.isEnabled = false
                    menu.addItem(rotItem)
                }

                let viewItem = NSMenuItem(title: "   📋 View Remediation Checklist & Actions...", action: viewIncidentAction, keyEquivalent: "")
                viewItem.target = target
                viewItem.tag = idx
                viewItem.representedObject = inc.id
                menu.addItem(viewItem)
            }

            menu.addItem(NSMenuItem.separator())
        }

        // 3. Security Flags Section
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

        // 4. Active Agents & Harness Tools Section
        let activeAgentsList = status?.agents ?? []
        let activeCount = max(status?.activeAgents ?? 0, activeAgentsList.count)
        let agentsHeader = NSMenuItem(title: "ACTIVE AGENTS & HARNESS TOOLS (\(activeCount))", action: nil, keyEquivalent: "")
        agentsHeader.isEnabled = false
        menu.addItem(agentsHeader)

        if activeCount == 0 && events.filter({ $0.kind == 8 }).isEmpty {
            let noneItem = NSMenuItem(title: "No active agent processes or tool activity", action: nil, keyEquivalent: "")
            noneItem.isEnabled = false
            menu.addItem(noneItem)
        } else {
            if !activeAgentsList.isEmpty {
                for agent in activeAgentsList {
                    var title = "🤖 \(agent.name) — PID \(agent.pid)"
                    if let cwd = agent.cwd, !cwd.isEmpty {
                        title += " (\(cwd))"
                    }
                    let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
                    item.isEnabled = false
                    menu.addItem(item)

                    let killItem = NSMenuItem(title: "   ⚡ Kill \(agent.name) Process (PID \(agent.pid))", action: killAction, keyEquivalent: "")
                    killItem.target = target
                    killItem.tag = Int(agent.pid)
                    menu.addItem(killItem)
                }
            }

            let pluginEvents = events.filter { $0.kind == 8 /* KindPluginAction */ }
            if !pluginEvents.isEmpty {
                let toolHeader = NSMenuItem(title: "   RECENT TOOL ACTIONS:", action: nil, keyEquivalent: "")
                toolHeader.isEnabled = false
                menu.addItem(toolHeader)

                for ev in pluginEvents.prefix(5) {
                    let toolName = ev.detail ?? "Tool"
                    let targetPath = ev.path ?? ""
                    let toolItem = NSMenuItem(title: "   🔨 \(toolName) → \(targetPath) (PID \(ev.pid))", action: nil, keyEquivalent: "")
                    toolItem.isEnabled = false
                    menu.addItem(toolItem)
                }
            }
        }

        menu.addItem(NSMenuItem.separator())

        // 5. Controls & System Actions
        let pauseTitle = isPaused ? "Resume Monitoring" : "Pause Monitoring"
        let pauseItem = NSMenuItem(title: pauseTitle, action: pauseAction, keyEquivalent: "")
        pauseItem.target = target
        menu.addItem(pauseItem)

        let refreshItem = NSMenuItem(title: "Refresh Now", action: refreshAction, keyEquivalent: "r")
        refreshItem.target = target
        menu.addItem(refreshItem)

        let dashItem = NSMenuItem(title: "Open Security Console", action: dashboardAction, keyEquivalent: "d")
        dashItem.target = target
        menu.addItem(dashItem)

        menu.addItem(NSMenuItem.separator())

        let setupItem = NSMenuItem(title: "Setup & Permissions…", action: setupAction, keyEquivalent: "")
        setupItem.target = target
        menu.addItem(setupItem)

        let uninstallItem = NSMenuItem(title: "Uninstall…", action: uninstallAction, keyEquivalent: "")
        uninstallItem.target = target
        menu.addItem(uninstallItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit Secure Agent", action: quitAction, keyEquivalent: "q")
        quitItem.target = target
        menu.addItem(quitItem)

        return menu
    }
}
