import AppKit

public final class MenuBuilder: @unchecked Sendable {

    /// Monochrome template SF Symbol for a menu item — follows the menu's text
    /// color for a clean, native look (no emoji, no hard-coded colors).
    private static func sym(_ name: String) -> NSImage? {
        let img = NSImage(systemSymbolName: name, accessibilityDescription: nil)
        img?.isTemplate = true
        return img
    }

    /// A disabled section header rendered in a small, tracked, secondary style.
    private static func sectionHeader(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 10, weight: .semibold),
            .foregroundColor: NSColor.tertiaryLabelColor,
            .kern: 0.6,
        ]
        item.attributedTitle = NSAttributedString(string: title.uppercased(), attributes: attrs)
        return item
    }

    public static func buildMenu(
        status: StatusResponse?,
        flags: [FlagModel],
        incidents: [IncidentReportModel],
        events: [EventModel],
        isPaused: Bool,
        target: AnyObject,
        refreshAction: Selector,
        killAction: Selector,
        promoteAction: Selector,
        viewIncidentAction: Selector,
        pauseAction: Selector,
        dashboardAction: Selector,
        setupAction: Selector,
        uninstallAction: Selector,
        quitAction: Selector
    ) -> NSMenu {
        let menu = NSMenu()

        // 1. Status
        let statusItem: NSMenuItem
        if let s = status, s.running {
            statusItem = NSMenuItem(title: "Active · uptime \(s.uptime)", action: nil, keyEquivalent: "")
            statusItem.image = sym("checkmark.circle.fill")
        } else {
            statusItem = NSMenuItem(title: "Disconnected", action: nil, keyEquivalent: "")
            statusItem.image = sym("xmark.circle.fill")
        }
        statusItem.isEnabled = false
        menu.addItem(statusItem)

        if let s = status, s.proxyEnabled == true, let port = s.proxyPort {
            let proxyItem = NSMenuItem(title: "Proxy active · 127.0.0.1:\(port)", action: nil, keyEquivalent: "")
            proxyItem.image = sym("lock.shield.fill")
            proxyItem.isEnabled = false
            menu.addItem(proxyItem)
        }

        if let s = status, let fw = s.firewallStats, !fw.isEmpty {
            let wouldBlock = fw.values.reduce(0) { $0 + $1.wouldBlock }
            let blocked = fw.values.reduce(0) { $0 + $1.blocked }
            let fwItem = NSMenuItem(title: "Firewall · \(wouldBlock) would-block · \(blocked) blocked", action: nil, keyEquivalent: "")
            fwItem.image = sym("shield.lefthalf.filled")
            fwItem.isEnabled = false
            menu.addItem(fwItem)

            for (rule, stat) in fw.sorted(by: { $0.key < $1.key }) where stat.wouldBlock > 0 {
                let promo = NSMenuItem(title: "Promote “\(rule)” to block (\(stat.wouldBlock))", action: promoteAction, keyEquivalent: "")
                promo.image = sym("arrow.up.circle.fill")
                promo.target = target
                promo.representedObject = rule
                menu.addItem(promo)
            }
        }

        if let s = status, let uninspected = s.uninspectedEgress, uninspected > 0 {
            let uItem = NSMenuItem(title: "Uninspected egress · \(uninspected) endpoint\(uninspected == 1 ? "" : "s")", action: nil, keyEquivalent: "")
            uItem.image = sym("eye.trianglebadge.exclamationmark")
            uItem.isEnabled = false
            menu.addItem(uItem)
        }

        menu.addItem(.separator())

        // 2. Incidents
        if !incidents.isEmpty {
            menu.addItem(sectionHeader("Incidents (\(incidents.count))"))
            for (idx, inc) in incidents.prefix(5).enumerated() {
                let sev = inc.risk == "CRITICAL" ? "[CRITICAL]" : "[HIGH]"
                let incItem = NSMenuItem(title: "\(sev) \(inc.rule) — PID \(inc.pid)", action: nil, keyEquivalent: "")
                incItem.image = sym(inc.risk == "CRITICAL" ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                incItem.isEnabled = false
                menu.addItem(incItem)

                for item in inc.rotateList {
                    let rotItem = NSMenuItem(title: "    Rotate \(item.name) (\(item.category))", action: nil, keyEquivalent: "")
                    rotItem.image = sym("key.fill")
                    rotItem.isEnabled = false
                    menu.addItem(rotItem)
                }

                let viewItem = NSMenuItem(title: "    View remediation…", action: viewIncidentAction, keyEquivalent: "")
                viewItem.image = sym("doc.text")
                viewItem.target = target
                viewItem.tag = idx
                viewItem.representedObject = inc.id
                menu.addItem(viewItem)
            }
            menu.addItem(.separator())
        }

        // 3. Security flags
        if !flags.isEmpty {
            menu.addItem(sectionHeader("Security flags (\(flags.count))"))
            for flag in flags {
                let sev = flag.severity >= 3 ? "[CRITICAL]" : "[WARN]"
                let flagItem = NSMenuItem(title: "\(sev) \(flag.rule) — \(flag.agent) (PID \(flag.pid))", action: nil, keyEquivalent: "")
                flagItem.image = sym(flag.severity >= 3 ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                flagItem.isEnabled = false
                menu.addItem(flagItem)

                for ev in flag.evidence {
                    let evItem = NSMenuItem(title: "        \(ev)", action: nil, keyEquivalent: "")
                    evItem.isEnabled = false
                    menu.addItem(evItem)
                }

                let killItem = NSMenuItem(title: "    Kill \(flag.agent) (PID \(flag.pid))", action: killAction, keyEquivalent: "")
                killItem.image = sym("bolt.fill")
                killItem.target = target
                killItem.tag = Int(flag.pid)
                menu.addItem(killItem)
            }
            menu.addItem(.separator())
        }

        // 4. Active agents & tool activity
        let activeAgentsList = status?.agents ?? []
        let activeCount = max(status?.activeAgents ?? 0, activeAgentsList.count)
        menu.addItem(sectionHeader("Active agents (\(activeCount))"))

        if activeCount == 0 && events.filter({ $0.kind == 8 }).isEmpty {
            let noneItem = NSMenuItem(title: "No active agents or tool activity", action: nil, keyEquivalent: "")
            noneItem.isEnabled = false
            menu.addItem(noneItem)
        } else {
            for agent in activeAgentsList {
                var title = "\(agent.name) — PID \(agent.pid)"
                if let cwd = agent.cwd, !cwd.isEmpty {
                    title += " (\(cwd))"
                }
                let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
                item.image = sym("cpu")
                item.isEnabled = false
                menu.addItem(item)

                let killItem = NSMenuItem(title: "    Kill \(agent.name) (PID \(agent.pid))", action: killAction, keyEquivalent: "")
                killItem.image = sym("bolt.fill")
                killItem.target = target
                killItem.tag = Int(agent.pid)
                menu.addItem(killItem)
            }

            let pluginEvents = events.filter { $0.kind == 8 /* KindPluginAction */ }
            if !pluginEvents.isEmpty {
                menu.addItem(sectionHeader("Recent tool actions"))
                for ev in pluginEvents.prefix(5) {
                    let toolName = ev.detail ?? "Tool"
                    let targetPath = ev.path ?? ""
                    let toolItem = NSMenuItem(title: "    \(toolName) → \(targetPath) (PID \(ev.pid))", action: nil, keyEquivalent: "")
                    toolItem.image = sym("hammer.fill")
                    toolItem.isEnabled = false
                    menu.addItem(toolItem)
                }
            }
        }

        menu.addItem(.separator())

        // 5. Controls
        let pauseItem = NSMenuItem(title: isPaused ? "Resume monitoring" : "Pause monitoring", action: pauseAction, keyEquivalent: "")
        pauseItem.image = sym(isPaused ? "play.circle" : "pause.circle")
        pauseItem.target = target
        menu.addItem(pauseItem)

        let refreshItem = NSMenuItem(title: "Refresh now", action: refreshAction, keyEquivalent: "r")
        refreshItem.image = sym("arrow.clockwise")
        refreshItem.target = target
        menu.addItem(refreshItem)

        let dashItem = NSMenuItem(title: "Open console", action: dashboardAction, keyEquivalent: "d")
        dashItem.image = sym("square.grid.2x2")
        dashItem.target = target
        menu.addItem(dashItem)

        menu.addItem(.separator())

        let setupItem = NSMenuItem(title: "Setup & Permissions…", action: setupAction, keyEquivalent: "")
        setupItem.image = sym("gearshape")
        setupItem.target = target
        menu.addItem(setupItem)

        let uninstallItem = NSMenuItem(title: "Uninstall…", action: uninstallAction, keyEquivalent: "")
        uninstallItem.image = sym("trash")
        uninstallItem.target = target
        menu.addItem(uninstallItem)

        menu.addItem(.separator())

        let quitItem = NSMenuItem(title: "Quit Secure Agent", action: quitAction, keyEquivalent: "q")
        quitItem.image = sym("power")
        quitItem.target = target
        menu.addItem(quitItem)

        return menu
    }
}
