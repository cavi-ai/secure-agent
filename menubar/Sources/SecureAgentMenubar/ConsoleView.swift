import SwiftUI

/// App palette, shared by every surface (popover, sheets, settings). Kept in
/// one place so a tint tweak doesn't need five edits. Both Color and
/// ShapeStyle surfaces are covered so `.brand` works in either inference
/// position (foregroundStyle/tint/foregroundStyle(Color)).
extension Color {
    static let brand = Color(.sRGB, red: 0.52, green: 0.44, blue: 0.97, opacity: 1)
    static let ok = Color(.sRGB, red: 0.30, green: 0.80, blue: 0.55, opacity: 1)
    static let warn = Color(.sRGB, red: 0.96, green: 0.62, blue: 0.20, opacity: 1)
    static let bad = Color(.sRGB, red: 0.92, green: 0.35, blue: 0.45, opacity: 1)
    /// The dim-but-visible text tier between .tertiary and .secondary.
    static let tertiaryText = Color(white: 0.62)
}

extension ShapeStyle where Self == Color {
    static var brand: Color { .brand }
    static var ok: Color { .ok }
    static var warn: Color { .warn }
    static var bad: Color { .bad }
}

extension FlagModel {
    /// Whether this flag's activity happened within the last minute — the
    /// row's "hot" styling cue (pulsing red vs. settled grey).
    var tsRecent: Bool {
        guard let t = EventTime.parse(ts) else { return false }
        return Date().timeIntervalSince(t) < 60
    }
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

    /// A collector the supervisor gave up on (e.g. eslogger without FDA) is
    /// the honest "why are transcripts thin / is this even monitoring"
    /// answer — silence otherwise reads as working.
    private func collectorBanner(_ collectors: [HealthModel]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(collectors) { h in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "waveform.path.ecg")
                        .font(.system(size: 11)).foregroundStyle(Color.warn)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(h.name) collector stopped — \(h.lastError ?? "repeated failures")")
                            .font(.system(size: 11)).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Text(esloggerHint(for: h))
                            .font(.system(size: 10)).foregroundStyle(.tertiary)
                    }
                    Spacer(minLength: 0)
                    Button { DaemonSupervisor.shared.restart(); state.refresh() } label: {
                        Text("Retry").font(.system(size: 10, weight: .semibold))
                    }
                    .buttonStyle(.bordered).controlSize(.mini).tint(Color.brand)
                }
                .padding(10)
                .background(Color.warn.opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    /// The fix that actually applies to this collector. eslogger's
    /// NOT_PRIVILEGED is NOT fixable by FDA — macOS requires the Endpoint
    /// Security client to run as root; honesty beats a placebo instruction.
    private func esloggerHint(for h: HealthModel) -> String {
        if h.name == "eslogger" && (h.lastError ?? "").contains("root") {
            return "macOS requires Endpoint Security (file telemetry) to run as root. A privileged collector helper ships with a future release — every other collector is unaffected."
        }
        return "Restart the app after granting Full Disk Access to retry."
    }

    private var sections: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let err = state.lastError { errorBanner(err) }
            if let abandoned = state.abandonedCollectors, !abandoned.isEmpty {
                collectorBanner(abandoned)
            }
            hero
            // Functional order: 1) needs-a-decision (incidents/criticals),
            // 2) what's running, 3) what's enforcing (quiet by design).
            if !state.incidents.isEmpty { incidentsSection }
            if !state.flags.isEmpty { flagsSection }
            if !state.agentRoots.isEmpty { agentsSection }
            firewallSection
            guardSection
        }
    }

    /// A collector the supervisor gave up on (e.g. eslogger without FDA) is
    /// the honest "why are transcripts thin / is this even monitoring"
    /// answer — silence otherwise reads as working.
    private func abandonedCollectorBanner(_ h: HealthModel) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "waveform.path.ecg")
                .font(.system(size: 11)).foregroundStyle(Color.warn)
            VStack(alignment: .leading, spacing: 2) {
                Text("\(h.name) collector stopped — \(h.lastError ?? "repeated failures")")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Restart the app after granting Full Disk Access to retry.")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
            }
            Spacer(minLength: 0)
            Button { DaemonSupervisor.shared.restart(); state.refresh() } label: {
                Text("Retry").font(.system(size: 10, weight: .semibold))
            }
            .buttonStyle(.bordered).controlSize(.mini).tint(Color.brand)
        }
        .padding(10)
        .background(Color.warn.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8))
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
        if state.isPaused {
            return ("pause.circle.fill", .secondary, "Paused",
                    "Alerts silenced — agents still run, decisions still prompt")
        }
        if !state.connected {
            return ("shield.slash", .secondary, "Disconnected",
                    "Not monitoring — the daemon is unreachable")
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
        let n = state.activeAgentCount
        let procs = state.trackedProcessCount
        let sub = procs > n
            ? "\(n) agent\(n == 1 ? "" : "s") monitored · \(procs) processes tracked · firewall \(state.isEnforcing ? "enforcing" : "monitoring")"
            : "\(n) agent\(n == 1 ? "" : "s") monitored · firewall \(state.isEnforcing ? "enforcing" : "monitoring")"
        return ("checkmark.shield.fill", .ok, "Protected", sub)
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
                    HStack(spacing: 7) {
                        Image(systemName: "cross.case.fill")
                            .font(.system(size: 11)).foregroundStyle(Color.bad)
                        AgentIdentity.tile(inc.agent, size: 14, fontSize: 8)
                        Text(Self.incidentRowTitle(inc.rule))
                            .font(.system(size: 11, weight: .medium))
                            .lineLimit(1)
                        Spacer()
                        if let t = relativeTime(inc.timestamp) {
                            Text(t)
                                .font(.system(size: 9, weight: .medium, design: .monospaced))
                                .foregroundStyle(.tertiary)
                        }
                        Image(systemName: "chevron.right")
                            .font(.system(size: 7, weight: .semibold)).foregroundStyle(.quaternary)
                    }
                }
                .buttonStyle(.plain)
                .help("\(Self.incidentRowTitle(inc.rule)) — \(inc.agent) · open the incident report")
            }
        }
        .sheet(item: $selectedIncident) { inc in
            IncidentDetailView(incident: inc, state: state)
        }
    }

    @State private var selectedIncident: IncidentReportModel?

    /// Row language for incidents: human title, not the raw rule id.
    static func incidentRowTitle(_ rule: String) -> String {
        switch rule {
        case "sensitive-read-then-connect": return "Read a secret, then connected out"
        case "proxy-secret-leak": return "Secret left in agent traffic"
        case "keychain-access": return "Touched your keychain"
        case "keychain-security-cli": return "Ran the keychain tool"
        case "tcc-tamper": return "Modified privacy permissions"
        case "proxy-prompt-injection": return "Prompt injection in a response"
        default: return rule
        }
    }

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
            // Dead space before — now the glanceable resource answer:
            // what agents cost, and how wide the monitoring net is.
            if state.connected {
                VStack(alignment: .trailing, spacing: 3) {
                    if let mem = ByteCount.short(state.totalAgentMemory) {
                        Label(mem, systemImage: "memorychip")
                            .font(.system(size: 10, weight: .semibold, design: .rounded))
                            .help("Total resident memory across all agent processes")
                    }
                    Label("\(state.trackedProcessCount)", systemImage: "cpu")
                        .font(.system(size: 10, weight: .medium, design: .rounded))
                        .foregroundStyle(.secondary)
                        .help("\(state.trackedProcessCount) processes · \(state.activeAgentCount) sessions")
                }
            }
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

    @State private var agentSort: AppState.AgentSort = .lastActivity
    /// Collapsed-by-default harness groups (persist within the popover's
    /// lifetime; a fresh open resets to the "expanded where it matters" state).
    @State private var expandedHarnesses: Set<String> = []
    @State private var selectedProcess: AgentSummaryModel?

    private var agentsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Agent sessions", trailing: "\(state.activeAgentCount)")

            // Sort control: three keys users actually want. A picker that
            // small still reads; segmented keeps it to one row.
            Picker("", selection: $agentSort) {
                ForEach(AppState.AgentSort.allCases, id: \.self) { s in
                    Text(s.label).tag(s)
                }
            }
            .pickerStyle(.segmented)
            .controlSize(.mini)
            .labelsHidden()

            if state.agentRoots.isEmpty {
                Text("No agents running — start one and it appears here")
                    .font(.system(size: 11)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                // Two-level: harness group (collapsible) → sessions
                // (collapsible) → subagents (nested, always visible when
                // the session is open).
                ForEach(state.harnessGroups(sortedBy: agentSort)) { group in
                    harnessGroupView(group)
                }
            }
        }
        .sheet(item: $selectedProcess) { proc in
            ProcessDetailSheet(agent: proc, state: state)
        }
    }

    /// Level 1: the harness (provider) — logo, session count, family memory.
    /// Collapsed by default when it has >1 session; a harness with exactly
    /// one session renders expanded (no information hidden behind a click
    /// for single-session users).
    private func harnessGroupView(_ group: AppState.HarnessGroup) -> some View {
        let expanded = expandedHarnesses.contains(group.name)
        let mem = ByteCount.short(group.totalRSSBytes)
        let seen = relativeTime(group.lastSeenAt ?? "")
        let isSingle = group.trees.count == 1
        return VStack(alignment: .leading, spacing: 3) {
            Button {
                if expanded {
                    expandedHarnesses.remove(group.name)
                } else {
                    expandedHarnesses.insert(group.name)
                }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: expanded && !isSingle ? "chevron.down" : "chevron.right")
                        .font(.system(size: 7, weight: .bold)).foregroundStyle(.secondary)
                        .frame(width: 8)
                    AgentIdentity.tile(group.name, size: 18)
                    Text(group.name)
                        .font(.system(size: 12, weight: .semibold))
                    if isSingle {
                        // A one-session harness IS the session — show its
                        // count inline instead of a pointless "+1".
                        if group.processCount > 1 {
                            Text("\(group.processCount) procs")
                                .font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                        }
                    } else {
                        Text("\(group.sessionCount) session\(group.sessionCount == 1 ? "" : "s") · \(group.processCount) procs")
                            .font(.system(size: 9)).foregroundStyle(.tertiary)
                    }
                    Spacer()
                    if let mem {
                        Text(mem)
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    if let seen {
                        Text(seen)
                            .font(.system(size: 9, weight: seen.hasSuffix("s") ? .semibold : .regular, design: .monospaced))
                            .foregroundStyle(seen.hasSuffix("s") ? Color.ok : .secondary)
                            .help("last activity: \(absoluteTime(group.lastSeenAt ?? ""))")
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded || isSingle {
                // Level 2+3: sessions with their subagents nested.
                ForEach(Array(group.trees.enumerated()), id: \.element.0.id) { _, pair in
                    sessionView(pair.0, children: pair.1, insideGroup: true)
                }
            }
        }
    }

    /// Level 2: one session (tree root) — expandable when it has subagents.
    /// Level 3 renders nested beneath it when expanded.
    @State private var expandedSessions: Set<String> = []

    private func sessionView(_ root: AgentSummaryModel, children: [AgentSummaryModel], insideGroup: Bool) -> some View {
        let hasKids = !children.isEmpty
        let open = expandedSessions.contains(root.id)
        let mem = ByteCount.short(root.rssBytes)
        let seen = relativeTime(root.lastSeenAt ?? "")
        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                // Expansion chevron (or indent dot when there's nothing to expand).
                Group {
                    if !children.isEmpty {
                        Button {
                            toggleSession(root.id)
                        } label: {
                            Image(systemName: expandedSessions.contains(root.id) ? "chevron.down" : "chevron.right")
                                .font(.system(size: 7, weight: .bold)).foregroundStyle(.secondary)
                                .frame(width: 10, height: 14)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    } else {
                        Color.clear.frame(width: 10, height: 10)
                    }
                }
                AgentIdentity.tile(root.name, size: 14, fontSize: 8)
                Button { selectedProcess = root } label: {
                    HStack(spacing: 5) {
                        Text("PID \(root.pid)")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(.primary)
                        if !children.isEmpty {
                            Text("+\(children.count)")
                                .font(.system(size: 8, weight: .semibold)).foregroundStyle(.tertiary)
                        }
                        if let mem {
                            Text(mem)
                                .font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                        }
                        if let seen {
                            Text(seen)
                                .font(.system(size: 9, weight: seen.hasSuffix("s") ? .semibold : .regular, design: .monospaced))
                                .foregroundStyle(seen.hasSuffix("s") ? Color.ok : Color(white: 0.6, opacity: 1))
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                Spacer(minLength: 0)
            }
            .padding(.leading, insideGroup ? 12 : 0)

            // Level 3: subagents, nested with a tree rail.
            if open && !children.isEmpty {
                ForEach(children, id: \.id) { child in
                    subagentRow(child)
                }
            }
        }
    }

    private func toggleSession(_ id: String) {
        if expandedSessions.contains(id) {
            expandedSessions.remove(id)
        } else {
            expandedSessions.insert(id)
        }
    }

    /// Level 3: a subagent, nested under its session with a tree elbow.
    private func subagentRow(_ child: AgentSummaryModel) -> some View {
        Button { selectedProcess = child } label: {
            HStack(spacing: 6) {
                Image(systemName: "arrow.turn.down.right")
                    .font(.system(size: 7)).foregroundStyle(.quaternary)
                    .padding(.leading, 34)
                AgentIdentity.tile(child.name, size: 13, fontSize: 7)
                Text(child.name)
                    .font(.system(size: 10, weight: .regular))
                    .foregroundStyle(.primary)
                Text("PID \(child.pid)")
                    .font(.system(size: 8, design: .monospaced)).foregroundStyle(.tertiary)
                if child.isOrphanLike {
                    Image(systemName: "questionmark.square")
                        .font(.system(size: 7)).foregroundStyle(Color.warn)
                        .help("parent already exited")
                }
                Spacer()
                if let m = ByteCount.short(child.rssBytes) {
                    Text(m)
                        .font(.system(size: 8, design: .monospaced)).foregroundStyle(.tertiary)
                }
                if let s = relativeTime(child.lastSeenAt ?? "") {
                    Text(s)
                        .font(.system(size: 8, weight: s.hasSuffix("s") ? .semibold : .regular, design: .monospaced))
                        .foregroundStyle(s.hasSuffix("s") ? Color.ok : Color(white: 0.6, opacity: 1))
                }
            }
            .padding(.leading, 12)
            .padding(.vertical, 1)
        }
        .buttonStyle(.plain)
    }

    @State private var manageRulesExpanded = false

    // MARK: flags

    private var flagsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Security flags", trailing: "\(state.flags.count)")
            // Every flag is a decision point: the whole row opens the action
            // sheet (evidence, dispositions, incident link). A critical you
            // can't act on is just anxiety with a badge.
            ForEach(state.flags.prefix(4)) { flag in
                Button { selectedFlag = flag } label: {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: flag.severity >= 3 ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                            .font(.system(size: 12)).foregroundStyle(flag.severity >= 3 ? Color.bad : Color.warn)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(Self.flagRowTitle(flag.rule))
                                .font(.system(size: 11, weight: .medium))
                            HStack(spacing: 5) {
                                AgentIdentity.tile(flag.agent, size: 13, fontSize: 7)
                                Text(flag.agent).font(.system(size: 9, weight: .medium)).foregroundStyle(.secondary)
                                if let t = relativeTime(flag.ts) {
                                    Text(t)
                                        .font(.system(size: 9, weight: flag.tsRecent ? .semibold : .regular, design: .monospaced))
                                        .foregroundStyle(flag.tsRecent ? Color.bad : Color.tertiaryText)
                                }
                            }
                            // Raw evidence stays in the action sheet —
                            // the list row answers "what/who/how fresh",
                            // not "here's a hex dump".
                        }
                        Spacer()
                        if flag.severity >= 3 {
                            Text("CRITICAL")
                                .font(.system(size: 8, weight: .bold))
                                .foregroundStyle(Color.bad)
                                .padding(.horizontal, 5).padding(.vertical, 3)
                                .background(Color.bad.opacity(0.14)).clipShape(Capsule())
                        }
                        Image(systemName: "chevron.right")
                            .font(.system(size: 7, weight: .semibold)).foregroundStyle(.quaternary)
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .sheet(item: $selectedFlag) { flag in
            FlagActionSheet(flag: flag, state: state)
        }
    }

    @State private var selectedFlag: FlagModel?

    /// Row language: human title, not the raw rule id.
    private static func flagRowTitle(_ rule: String) -> String {
        switch rule {
        case "sensitive-read-then-connect": return "Read a secret, then connected out"
        case "proxy-secret-leak": return "Secret left in agent traffic"
        case "keychain-access": return "Touched your keychain"
        case "keychain-security-cli": return "Ran the keychain tool"
        case "tcc-tamper": return "Modified privacy permissions"
        case "proxy-prompt-injection": return "Prompt injection in a response"
        default: return rule
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
            .disabled(state.dashboardUnavailableReason != nil)
            .help(state.dashboardUnavailableReason ?? "Open the web console")
            Spacer()
            Button { SettingsWindowController.shared.show(state: state) } label: {
                Image(systemName: "gearshape").font(.system(size: 13))
            }.buttonStyle(.borderless).help("Settings")
            Button { state.togglePause() } label: {
                Image(systemName: state.isPaused ? "play.circle" : "pause.circle").font(.system(size: 14))
            }.buttonStyle(.borderless).help(state.isPaused ? "Resume alerts" : "Pause alerts")
            Button { state.refresh() } label: {
                Image(systemName: "arrow.clockwise").font(.system(size: 13))
            }
            .buttonStyle(.borderless)
            .disabled(state.isPaused)
            .help(state.isPaused ? "Paused — resume to refresh" : "Refresh")
            Button { NSApp.terminate(nil) } label: {
                Image(systemName: "power").font(.system(size: 13))
            }
            .buttonStyle(.borderless)
            .help("Quit Secure Agent (⌘Q)")
            .keyboardShortcut("q", modifiers: .command)
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
