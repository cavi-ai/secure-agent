import SwiftUI

private extension Color {
    static let brand = Color(.sRGB, red: 0.52, green: 0.44, blue: 0.97, opacity: 1)
    static let ok = Color(.sRGB, red: 0.30, green: 0.80, blue: 0.55, opacity: 1)
    static let warn = Color(.sRGB, red: 0.96, green: 0.62, blue: 0.20, opacity: 1)
    static let bad = Color(.sRGB, red: 0.92, green: 0.35, blue: 0.45, opacity: 1)
}

/// The menu-bar popover: a compact, premium mini-console. Deep views (full
/// history, incident reports, rotation) live in the web console via "Open console".
@MainActor
struct ConsoleView: View {
    @ObservedObject var state: AppState
    @ObservedObject private var supervisor = DaemonSupervisor.shared
    /// Preview/snapshot renderers don't lay out ScrollView content; set false to
    /// render the sections in a plain stack for snapshots.
    var scrollable: Bool = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if scrollable {
                ScrollView { sections.padding(14) }.frame(maxHeight: 420)
            } else {
                sections.padding(14)
            }
            Divider()
            footer
        }
        .frame(width: 340)
    }

    private var sections: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let err = state.lastError { errorBanner(err) }
            hero
            if !state.incidents.isEmpty { incidentsSection }
            firewallSection
            guardSection
            if !state.activeAgents.isEmpty { agentsSection }
            if !state.flags.isEmpty { flagsSection }
        }
    }

    // MARK: hero

    /// The one-glance answer, mirroring the web console's posture banner:
    /// Protected / Attention / Action needed (+ Disconnected). Everything
    /// below the hero is drill-down; the hero is what most opens should need.
    private var hero: some View {
        let m = heroModel
        return HStack(spacing: 12) {
            Image(systemName: m.icon)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(m.color)
                .frame(width: 38, height: 38)
                .background(m.color.opacity(0.14))
                .clipShape(RoundedRectangle(cornerRadius: 9))
            VStack(alignment: .leading, spacing: 2) {
                Text(m.title).font(.system(size: 14, weight: .bold))
                Text(m.subtitle).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(m.color.opacity(0.07))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .animation(.easeInOut(duration: 0.25), value: m.title)
    }

    private var heroModel: (icon: String, color: Color, title: String, subtitle: String) {
        if !state.connected {
            return ("shield.slash", .secondary, "Disconnected",
                    "Monitoring paused — the daemon is unreachable")
        }
        let criticalFlags = state.flags.filter { $0.severity >= 3 }.count
        if !state.incidents.isEmpty || criticalFlags > 0 {
            var parts: [String] = []
            if !state.incidents.isEmpty {
                parts.append("\(state.incidents.count) incident\(state.incidents.count == 1 ? "" : "s")")
            }
            if criticalFlags > 0 {
                parts.append("\(criticalFlags) critical flag\(criticalFlags == 1 ? "" : "s")")
            }
            // The fatigue reducer: the local advisor already triaged some of
            // these as likely benign — say so at the glance level.
            let benign = state.flags.filter { $0.severity >= 3 && $0.advisor?.assessment == "benign" }.count
            if benign > 0 { parts.append("advisor: \(benign) likely benign") }
            return ("exclamationmark.shield.fill", .bad, "Action needed",
                    parts.joined(separator: " · "))
        }
        let warnFlags = state.flags.filter { $0.severity >= 2 }.count
        if warnFlags > 0 || state.uninspectedEgress > 0 || state.firewallWouldBlock > 0 {
            var parts: [String] = []
            if warnFlags > 0 { parts.append("\(warnFlags) flag\(warnFlags == 1 ? "" : "s") to review") }
            if state.firewallWouldBlock > 0 { parts.append("\(state.firewallWouldBlock) would-block") }
            if state.uninspectedEgress > 0 { parts.append("\(state.uninspectedEgress) uninspected") }
            return ("exclamationmark.triangle.fill", .warn, "Attention",
                    parts.joined(separator: " · "))
        }
        let n = state.activeAgents.count
        return ("checkmark.shield.fill", .ok, "Protected",
                "\(n) agent\(n == 1 ? "" : "s") monitored · firewall \(state.isEnforcing ? "enforcing" : "monitoring")")
    }

    // MARK: incidents

    /// Open incidents with their remediation checklists — the daemon already
    /// generates these reports; this surfaces them where the user actually
    /// looks instead of only in the web console.
    private var incidentsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Incidents", trailing: "\(state.incidents.count)")
            ForEach(state.incidents.prefix(3)) { inc in
                Button { selectedIncident = inc } label: {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "cross.case.fill")
                            .font(.system(size: 12)).foregroundStyle(Color.bad)
                        VStack(alignment: .leading, spacing: 1) {
                            Text("\(inc.rule) — \(inc.agent)").font(.system(size: 11, weight: .medium))
                            Text(inc.summary).font(.system(size: 10)).foregroundStyle(.tertiary).lineLimit(2)
                        }
                        Spacer()
                        Text(inc.risk.uppercased()).font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Color.bad)
                            .padding(.horizontal, 7).padding(.vertical, 4)
                            .background(Color.bad.opacity(0.14)).clipShape(Capsule())
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .sheet(item: $selectedIncident) { inc in
            IncidentDetailView(incident: inc)
        }
    }

    @State private var selectedIncident: IncidentReportModel?

    // MARK: error surfacing

    /// Daemon problems are visible, not just a grey dot: transport failures,
    /// decode mismatches, refused kills, and dropped guard decisions all land
    /// here instead of vanishing into a disconnected state.
    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 11)).foregroundStyle(Color.warn)
            Text(message).font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.warn.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(LinearGradient(colors: [.brand, Color(.sRGB, red: 0.62, green: 0.36, blue: 0.9, opacity: 1)],
                                           startPoint: .topLeading, endPoint: .bottomTrailing))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 1) {
                Text("Secure Agent").font(.system(size: 13, weight: .bold))
                HStack(spacing: 5) {
                    Circle().fill(state.connected ? Color.ok : Color.bad).frame(width: 6, height: 6)
                    Text(state.statusText).font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
        .padding(.horizontal, 14).padding(.vertical, 11)
    }

    // MARK: firewall

    private var firewallSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Egress firewall", trailing: state.isEnforcing ? "enforcing" : "monitor",
                          trailingColor: state.isEnforcing ? .ok : .secondary, trailingMonospaced: false)

            if state.firewallRules.isEmpty {
                Text("No egress inspected yet — traffic is scanned as your agents run")
                    .font(.system(size: 11)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                if state.uninspectedEgress > 0 {
                    Label("\(state.uninspectedEgress) endpoint\(state.uninspectedEgress == 1 ? "" : "s") reached without inspection",
                          systemImage: "globe")
                        .font(.system(size: 11)).foregroundStyle(Color.warn)
                        .fixedSize(horizontal: false, vertical: true)
                }
                // Condensed: only rules that have seen suspicious traffic earn a
                // row. Quiet rules (legit traffic only) collapse into one line —
                // the popover answers questions, it doesn't host dashboards.
                let active = state.firewallRules.filter { $0.stat.wouldBlock > 0 || $0.stat.blocked > 0 }
                if active.isEmpty {
                    Text("\(state.firewallRules.count) rule\(state.firewallRules.count == 1 ? "" : "s") active · no suspicious egress")
                        .font(.system(size: 11)).foregroundStyle(.tertiary)
                } else {
                    ForEach(active) { rule in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(rule.id).font(.system(size: 12, weight: .semibold, design: .monospaced))
                                Text("\(rule.stat.wouldBlock) would-block · \(rule.stat.blocked) blocked")
                                    .font(.system(size: 10)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if rule.stat.mode == "block" {
                                Text("BLOCKING").font(.system(size: 9, weight: .bold))
                                    .foregroundStyle(Color.ok)
                                    .padding(.horizontal, 7).padding(.vertical, 4)
                                    .background(Color.ok.opacity(0.14)).clipShape(Capsule())
                            } else {
                                Button { state.promote(rule: rule.id) } label: {
                                    Label("Block", systemImage: "arrow.up.circle.fill").font(.system(size: 11, weight: .semibold))
                                }
                                .buttonStyle(.borderedProminent).tint(.brand).controlSize(.small)
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: guard

    private static let guardRuleLabels: [(id: String, label: String)] = [
        ("ssh-keys", "SSH private keys"),
        ("cloud-creds", "Cloud credentials"),
        ("keychain", "Keychain"),
        ("env-files", ".env files"),
        ("shell-rc", "Shell config"),
        ("harness-config", "Harness config & hooks"),
    ]

    private var guardSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Directory guard", trailing: "\(state.guardRules.count)")

            // Per-rule policy lives behind a disclosure: the popover answers
            // "am I protected / did anything happen" at a glance; the
            // monitor/prompt/deny editor is opened deliberately.
            DisclosureGroup(isExpanded: $manageRulesExpanded) {
                guardPolicyEditor.padding(.top, 6)
            } label: {
                Text("Manage rules…").font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
            }

            if state.guardRules.isEmpty {
                Text("No guard decisions yet — sensitive paths are prompted on first access")
                    .font(.system(size: 11)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(state.guardRules) { rule in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(rule.agent).font(.system(size: 12, weight: .semibold))
                                Text(rule.ruleID).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
                            }
                            Text("\(rule.decision) · \(rule.source)")
                                .font(.system(size: 10)).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(rule.decision.uppercased()).font(.system(size: 9, weight: .bold))
                            .foregroundStyle(rule.decision == "allow" ? Color.ok : Color.bad)
                            .padding(.horizontal, 7).padding(.vertical, 4)
                            .background((rule.decision == "allow" ? Color.ok : Color.bad).opacity(0.14)).clipShape(Capsule())
                        Button { state.revokeGuardRule(agent: rule.agent, ruleID: rule.ruleID) } label: {
                            Label("Revoke", systemImage: "trash").font(.system(size: 11, weight: .semibold))
                        }
                        .buttonStyle(.bordered).controlSize(.small)
                    }
                }
            }
            Text("Hook decisions can block; monitored accesses are observed only")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: guard policy editor

    /// Per-rule monitor/prompt/deny toggles, persisted straight to
    /// guard-modes.json (atomic write; the hook reads it per tool call, so no
    /// daemon round-trip exists). A corrupt file is surfaced, not hidden —
    /// the hook fails closed on it.
    private var guardPolicyEditor: some View {
        let current = SetupManager.shared.currentGuardModes()
        return VStack(alignment: .leading, spacing: 6) {
            if current.corrupt {
                Label("guard-modes.json is unreadable — the guard is failing closed (deny) until fixed",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 10)).foregroundStyle(Color.bad)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(Self.guardRuleLabels, id: \.id) { rule in
                HStack {
                    Text(rule.label).font(.system(size: 11))
                    Spacer()
                    Picker("", selection: Binding(
                        get: { current.modes[rule.id] ?? "monitor" },
                        set: { newMode in
                            do {
                                try SetupManager.shared.setGuardMode(ruleID: rule.id, mode: newMode)
                                // Re-render from the file we just wrote.
                                state.refresh()
                            } catch {
                                state.reportLocalError("could not set \(rule.id): \(error.localizedDescription)")
                            }
                        }
                    )) {
                        Text("Monitor").tag("monitor")
                        Text("Prompt").tag("prompt")
                        Text("Deny").tag("deny")
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 170)
                    .labelsHidden()
                }
            }
        }
    }

    // MARK: agents

    private var agentsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Active agents", trailing: "\(state.activeAgents.count)")
            ForEach(state.activeAgents) { agent in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(agent.name).font(.system(size: 12, weight: .semibold))
                            Text("PID \(agent.pid)").font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary)
                        }
                        if let cwd = agent.cwd, !cwd.isEmpty {
                            Text(cwd).font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary).lineLimit(1)
                        }
                    }
                    Spacer()
                    Button(role: .destructive) { killTarget = agent } label: {
                        Label("Kill", systemImage: "power").font(.system(size: 11, weight: .semibold))
                    }
                    .buttonStyle(.bordered).controlSize(.small)
                }
            }
        }
        // One click used to SIGKILL the user's agent with no undo and no
        // confirmation. Confirm explicitly.
        .confirmationDialog(
            "Kill this agent process?",
            isPresented: Binding(get: { killTarget != nil }, set: { if !$0 { killTarget = nil } }),
            titleVisibility: .visible
        ) {
            Button("Kill \(killTarget?.name ?? "") (pid \(killTarget?.pid ?? 0))", role: .destructive) {
                if let pid = killTarget?.pid { state.kill(pid: pid) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The agent process tree is terminated immediately. Unsaved work in it is lost.")
        }
    }

    @State private var killTarget: AgentSummaryModel?
    @State private var manageRulesExpanded = false

    // MARK: flags

    private var flagsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Security flags", trailing: "\(state.flags.count)")
            ForEach(state.flags.prefix(4)) { flag in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: flag.severity >= 3 ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 12)).foregroundStyle(flag.severity >= 3 ? Color.bad : Color.warn)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("\(flag.rule) — \(flag.agent)").font(.system(size: 11, weight: .medium))
                        if let sid = flag.sessionId, !sid.isEmpty {
                            // The evidence-chain link: which harness session
                            // produced this flag, surviving PID reuse.
                            Text("session \(sid.prefix(8))").font(.system(size: 9, design: .monospaced))
                                .foregroundStyle(.quaternary)
                        }
                        if let ev = flag.evidence.first {
                            Text(ev).font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary).lineLimit(2)
                        }
                    }
                    Spacer()
                }
            }
        }
    }

    // MARK: footer

    private var footer: some View {
        VStack(spacing: 8) {
            if supervisor.gaveUpRestarting {
                // The restart limiter gave up: without this the popover just
                // says "Disconnected" forever with no way back.
                HStack(spacing: 8) {
                    Label("Daemon crashed repeatedly and was left stopped", systemImage: "exclamationmark.octagon.fill")
                        .font(.system(size: 11)).foregroundStyle(Color.bad)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button { supervisor.restart(); state.refresh() } label: {
                        Text("Restart").font(.system(size: 11, weight: .semibold))
                    }
                    .buttonStyle(.borderedProminent).tint(.brand).controlSize(.small)
                }
                .padding(10)
                .background(Color.bad.opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            HStack(spacing: 8) {
            Button { state.openDashboard() } label: {
                Label("Open console", systemImage: "square.grid.2x2").font(.system(size: 12, weight: .semibold))
            }
            .buttonStyle(.borderedProminent).tint(.brand).controlSize(.regular)
            Spacer()
            Button { SettingsWindowController.shared.show(state: state) } label: {
                Image(systemName: "gearshape").font(.system(size: 13))
            }.buttonStyle(.borderless).help("Settings")
            Button { state.togglePause() } label: {
                Image(systemName: state.isPaused ? "play.circle" : "pause.circle").font(.system(size: 14))
            }.buttonStyle(.borderless).help(state.isPaused ? "Resume monitoring" : "Pause monitoring")
            Button { state.refresh() } label: {
                Image(systemName: "arrow.clockwise").font(.system(size: 13))
            }.buttonStyle(.borderless).help("Refresh")
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private func sectionHeader(_ title: String, trailing: String, trailingColor: Color = .secondary, trailingMonospaced: Bool = true) -> some View {
        HStack {
            Text(title.uppercased()).font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary).kerning(0.5)
            Spacer()
            Text(trailing).font(.system(size: 10, weight: .semibold, design: trailingMonospaced ? .monospaced : .default))
                .foregroundStyle(trailingColor)
        }
    }
}
