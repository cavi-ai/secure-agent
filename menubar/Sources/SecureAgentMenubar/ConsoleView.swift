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
            if !state.incidents.isEmpty || !state.unactedFlags.isEmpty { attentionSection }
            if !state.agentRoots.isEmpty { agentsSection }
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
    /// The hero IS the action when action is needed: subtitle says what to
    /// do (the advisor's recommendation or the top flag), tapping it opens
    /// that flag's action sheet. Prose-first: "cursor read a key file and
    /// connected out — allow or rotate", not "1 incident · 2 critical flags".
    private var hero: some View {
        let m = heroModel
        let actionable = m.actionTarget != nil
        return Button {
            if let target = m.actionTarget { selectedFlag = target }
        } label: {
            HStack(spacing: 12) {
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
                if actionable {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(m.color.opacity(0.7))
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(m.color.opacity(0.07))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!actionable)
        .animation(.easeInOut(duration: 0.25), value: m.title)
    }

    private var heroModel: (icon: String, color: Color, title: String, subtitle: String, actionTarget: FlagModel?) {
        if state.isPaused {
            return ("pause.circle.fill", .secondary, "Paused",
                    "Alerts silenced — agents still run, decisions still prompt", nil)
        }
        if !state.connected {
            return ("shield.slash", .secondary, "Disconnected",
                    "Not monitoring — the daemon is unreachable", nil)
        }
        let criticalFlags = state.flags.filter { $0.severity >= 3 && $0.acknowledged != true }.count
        if !state.incidents.isEmpty || criticalFlags > 0 {
            var parts: [String] = []
            // Prose-first: name what happened + what to do, not counts.
            // The top critical flag (advisor-ordered when triaged) IS the
            // action; the hero subtitle says it in one sentence.
            let top = state.flags.first { $0.severity >= 3 && $0.acknowledged != true }
                ?? state.incidents.first.map { inc in
                    FlagModel(id: inc.flagId, rule: inc.rule, severity: 3, ts: inc.timestamp,
                              pid: inc.pid, agent: inc.agent, evidence: [])
                }
            if let top {
                let what: String
                switch top.rule {
                case "sensitive-read-then-connect":
                    what = "\(top.agent) read a sensitive file, then connected out"
                case "proxy-secret-leak":
                    what = "\(top.agent) sent a secret to a remote host"
                case "keychain-access":
                    what = "\(top.agent) opened your keychain"
                case "keychain-security-cli":
                    what = "\(top.agent) read keychain secrets via the CLI"
                case "tcc-tamper":
                    what = "\(top.agent) changed app permissions without asking"
                case "proxy-prompt-injection":
                    what = "a response to \(top.agent) contained an injection attempt"
                default:
                    what = "\(top.agent) triggered \(top.rule)"
                }
                let advice: String
                switch top.advisor?.suggestedAction {
                case "allow-host": advice = "tap to allow the host"
                case "mute-rule": advice = "tap to dismiss this flag class"
                case "rotate-credentials": advice = "tap to rotate the credential"
                case "kill-agent": advice = "tap to stop the agent"
                default: advice = "tap to review"
                }
                return ("exclamationmark.shield.fill", .bad, "Action needed",
                        "\(what) — \(advice).", top)
            }
            return ("exclamationmark.shield.fill", .bad, "Action needed",
                    "Review the flagged activity.", nil)
        }
        let warnFlags = state.flags.filter { $0.severity >= 2 }.count
        if warnFlags > 0 || state.uninspectedEgress > 0 || state.firewallWouldBlock > 0 {
            var parts: [String] = []
            if warnFlags > 0 { parts.append("\(warnFlags) flag\(warnFlags == 1 ? "" : "s") to review") }
            if state.firewallWouldBlock > 0 { parts.append("\(state.firewallWouldBlock) would-block") }
            if state.uninspectedEgress > 0 { parts.append("\(state.uninspectedEgress) uninspected") }
            return ("exclamationmark.triangle.fill", .warn, "Attention",
                    parts.joined(separator: " · "), nil)
        }
        let n = state.activeAgentCount
        let procs = state.trackedProcessCount
        let sub = procs > n
            ? "\(n) agent\(n == 1 ? "" : "s") monitored · \(procs) processes tracked · firewall \(state.isEnforcing ? "enforcing" : "monitoring")"
            : "\(n) agent\(n == 1 ? "" : "s") monitored · firewall \(state.isEnforcing ? "enforcing" : "monitoring")"
        return ("checkmark.shield.fill", .ok, "Protected", sub, nil)
    }

    // MARK: incidents

    /// Open incidents with their remediation checklists — the daemon already
    /// generates these reports; this surfaces them where the user actually
    /// looks instead of only in the web console.
    /// One "needs attention" section: incidents with remediation sheets, then
    /// flags without an incident (action sheets). The same underlying problem
    /// never appears twice — if it has an incident, it's an incident row.
    private var attentionSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            let unflagged = state.incidents.count
            let flagOnly = state.flags.filter { f in
                f.acknowledged != true && !state.incidents.contains { $0.flagId == f.id }
            }
            let total = unflagged + flagOnly.count
            sectionHeader("Needs attention", trailing: "\(total)")
            if !state.incidents.isEmpty {
                incidentRows
            }
            ForEach(flagOnly.prefix(4)) { flag in
                flagRow(flag)
            }
        }
        .sheet(item: $selectedIncident) { inc in
            IncidentDetailView(incident: inc, state: state)
        }
        .sheet(item: $selectedFlag) { flag in
            FlagActionSheet(flag: flag, state: state)
        }
    }

    private var incidentRows: some View {
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


    // MARK: flags

    /// One flag row (used by attentionSection for flags without an incident).
    private func flagRow(_ flag: FlagModel) -> some View {
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
                }
                Spacer()
                if flag.acknowledged == true {
                    Text("DONE")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundStyle(Color.ok)
                        .padding(.horizontal, 5).padding(.vertical, 3)
                        .background(Color.ok.opacity(0.14)).clipShape(Capsule())
                } else if flag.severity >= 3 {
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
        .opacity(flag.acknowledged == true ? 0.45 : 1.0)
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
