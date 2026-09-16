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
            if let notice = state.advisorNotice { advisorNoticeBanner(notice) }
            if let abandoned = state.abandonedCollectors, !abandoned.isEmpty {
                collectorBanner(abandoned)
            }
            hero
            // Functional order: 1) needs-a-decision (incidents/criticals),
            // 2) what's running, 3) what's enforcing (quiet by design).
            if !attentionIsEmpty { attentionSection }
            if !state.agentRoots.isEmpty { agentsSection }
        }
    }

    /// Advisor lifecycle feedback ("verdict updated", "advisor offline") —
    /// dismissable, auto-clears so it doesn't become its own noise source.
    private func advisorNoticeBanner(_ notice: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "brain")
                .font(.system(size: 11)).foregroundStyle(Color.brand)
            Text(notice)
                .font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button { state.clearAdvisorNotice() } label: {
                Image(systemName: "xmark").font(.system(size: 9, weight: .bold))
            }
            .buttonStyle(.plain).foregroundStyle(.tertiary)
        }
        .padding(10)
        .background(Color.brand.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .task(id: notice) {
            // Auto-clear after 12s: a notice that lingers becomes noise.
            try? await Task.sleep(nanoseconds: 12_000_000_000)
            state.clearAdvisorNotice(matching: notice)
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
    private var attentionIsEmpty: Bool {
        state.unactedFlagsForSession(rootPid: selectedSessionRoot).isEmpty
            && scopedOpenIncidents.isEmpty
    }

    private var scopedOpenIncidents: [IncidentReportModel] {
        let pids = selectedSessionRoot.map { state.treePIDs(rootPid: $0) }
        return state.incidents.filter { inc in
            if let pids, !pids.contains(inc.pid) { return false }
            guard let flag = state.flags.first(where: { $0.id == inc.flagId }) else { return true }
            return flag.acknowledged != true && inc.workflow?.status != "resolved"
        }
    }

    /// One "needs attention" section: incidents with remediation sheets, then
    /// flags without an incident (action sheets). The same underlying problem
    /// never appears twice — if it has an incident, it's an incident row.
    private var attentionSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            let groups = state.groupedUnactedFlags(forRootPid: selectedSessionRoot)
            let openIncidents = scopedOpenIncidents
            // One row per group: a group whose flags carry incidents opens the
            // NEWEST incident (remediation) on tap — the incident never renders
            // as its own duplicate row.
            let rows = attentionRows(groups: groups, openIncidents: openIncidents)
            // Incidents with no matching flag group render standalone.
            let groupedFlagIds = Set(groups.flatMap { $0.flags.map(\.id) })
            let standaloneIncidents = openIncidents.filter { !groupedFlagIds.contains($0.flagId) }
            let total = rows.count + standaloneIncidents.count
            sectionHeader("Needs attention", trailing: selectedSessionRoot == nil ? "\(total)" : "\(total) in session")
            ForEach(rows.prefix(4)) { row in
                flagGroupRow(row.group, asIncident: row.incident)
            }
            ForEach(standaloneIncidents.prefix(3)) { inc in
                incidentRow(inc)
            }
        }
        .sheet(item: $selectedIncident) { inc in
            IncidentDetailView(incident: inc, state: state)
        }
        .sheet(item: $selectedFlag) { flag in
            FlagActionSheet(flag: flag, state: state)
        }
        .confirmationDialog(
            "Dismiss this flag class?",
            isPresented: Binding(get: { confirmIgnoreGroup != nil }, set: { if !$0 { confirmIgnoreGroup = nil } }),
            titleVisibility: .visible
        ) {
            Button("Dismiss", role: .destructive) {
                if let g = confirmIgnoreGroup { Task { await ignoreFlagGroup(g) } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Stop flagging \(Self.flagRowTitle(confirmIgnoreGroup?.rule ?? "")) for \(confirmIgnoreGroup?.agent ?? "") in this context. Existing rows clear; monitoring continues.")
        }
    }

    /// Ignore-class on a group: mute (rule, host) + acknowledge every flag
    /// in the group. One gesture, the whole pattern goes quiet. Hostless
    /// rules (keychain file/exec evidence has no connection target) fall
    /// back to the rule-level disposition (host "*") — the old guard just
    /// errored out, leaving keychain rows with "no resolution possible".
    private func ignoreFlagGroup(_ group: AppState.FlagGroup) async {
        let host = FlagActionSheet.muteHost(evidence: group.newest.evidence)
        do {
            try await state.uiClient.muteAdd(rule: group.rule, host: host)
            for f in group.flags {
                try? await state.uiClient.acknowledgeFlag(id: f.id)
            }
            state.refresh()
        } catch {
            state.reportLocalError("dismiss failed: \(error.localizedDescription)")
        }
    }

    private func incidentRow(_ inc: IncidentReportModel) -> some View {
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

    private func incidentRows(_ incidents: [IncidentReportModel]) -> some View {
        ForEach(incidents.prefix(3)) { inc in
        }
        .sheet(item: $selectedIncident) { inc in
            IncidentDetailView(incident: inc, state: state)
        }
        .sheet(item: $selectedFlag) { flag in
            FlagActionSheet(flag: flag, state: state)
        }
    }

    /// One row per flag GROUP: "touched your keychain ×20 · codex · 2d".
    /// The count badge makes repeats honest; the whole row opens the sheet
    /// (which acts on the newest), with an inline ignore-class shortcut.
    /// One row per flag GROUP. When the group's flags carry an incident, the
    /// row opens the NEWEST incident (remediation) instead of the flag sheet —
    /// one row, one destination, never a duplicate.
    private func flagGroupRow(_ group: AppState.FlagGroup, asIncident: IncidentReportModel?) -> some View {
        let newest = group.newest
        let seen = relativeTime(group.newest.ts)
        return HStack(alignment: .top, spacing: 8) {
            Image(systemName: newest.severity >= 3 ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 12)).foregroundStyle(newest.severity >= 3 ? Color.bad : Color.warn)
            VStack(alignment: .leading, spacing: 1) {
                Text(Self.flagRowTitle(group.rule))
                    .font(.system(size: 11, weight: .medium))
                HStack(spacing: 5) {
                    AgentIdentity.tile(group.agent, size: 13, fontSize: 7)
                    Text(group.agent).font(.system(size: 9, weight: .medium)).foregroundStyle(.secondary)
                    if group.count > 1 {
                        Text("×\(group.count)")
                            .font(.system(size: 9, weight: .bold, design: .rounded))
                            .foregroundStyle(Color.bad)
                            .help("\(group.count) identical fires of this pattern")
                    }
                    if let seen {
                        Text(seen)
                            .font(.system(size: 9, weight: seen.hasSuffix("s") ? .semibold : .regular, design: .monospaced))
                            .foregroundStyle(seen.hasSuffix("s") ? Color.bad : Color.tertiaryText)
                    }
                }
            }
            Spacer()
            Button { confirmIgnoreGroup = group } label: {
                Image(systemName: "eye.slash")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
                    .padding(4)
                    .background(Color.primary.opacity(0.04))
                    .clipShape(Capsule())
            }
            .buttonStyle(.plain)
            .help("Dismiss this flag class (rule + host) — stops future fires and clears these rows")
            Image(systemName: "chevron.right")
                .font(.system(size: 7, weight: .semibold)).foregroundStyle(.quaternary)
        }
        .opacity(newest.acknowledged == true ? 0.45 : 1.0)
        .contentShape(Rectangle())
        .onTapGesture {
            if let asIncident {
                selectedIncident = asIncident
            } else {
                selectedFlag = newest
            }
        }
    }

    @State private var confirmIgnoreGroup: AppState.FlagGroup?

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
                    if let host = state.resources?.host,
                       let available = ByteCount.short(host.availableMemoryBytes) {
                        Label("\(available) available · \(host.headroomScore)/100", systemImage: "gauge.with.dots.needle.33percent")
                            .font(.system(size: 10, weight: .semibold, design: .rounded))
                            .foregroundStyle(host.capacity == "critical" ? Color.bad : host.capacity == "constrained" ? Color.warn : Color.ok)
                            .help("Machine headroom · \(host.memoryPressure) memory pressure · \(host.thermalState) thermal · agents \(ByteCount.short(host.agentMemoryBytes) ?? "unavailable") · other apps \(ByteCount.short(host.nonAgentMemoryBytes) ?? "unavailable")")
                    }
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
    @State private var selectedProcess: AgentSummaryModel?
    @State private var selectedSessionRoot: Int32?

    private var agentsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Sessions", trailing: "\(state.sessionBoardRows(sortedBy: agentSort).count)")

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
                ForEach(state.sessionBoardRows(sortedBy: agentSort)) { row in
                    sessionView(row.agent, children: children(of: row.agent), insideGroup: false)
                }
            }
        }
        .sheet(item: $selectedProcess) { proc in
            ProcessDetailSheet(agent: proc, state: state)
        }
    }

    private func children(of root: AgentSummaryModel) -> [AgentSummaryModel] {
        state.childAgents.filter { $0.rootPid == root.pid }
    }

    /// Level 2: one session (tree root) — expandable when it has subagents.
    /// Level 3 renders nested beneath it when expanded.
    @State private var expandedSessions: Set<String> = []

    private func sessionView(_ root: AgentSummaryModel, children: [AgentSummaryModel], insideGroup: Bool) -> some View {
        let open = expandedSessions.contains(root.id)
        let rssParts = ([root] + children).compactMap(\.rssBytes)
        let mem = rssParts.isEmpty ? nil : ByteCount.short(rssParts.reduce(0, +))
        let cpuParts = ([root] + children).compactMap(\.cpuPercent)
        let cpu = cpuParts.isEmpty ? nil : cpuParts.reduce(0, +)
        let seen = relativeTime(([root] + children).compactMap(\.lastSeenAt).max() ?? "")
        let flagN = state.unactedFlagsForSession(rootPid: root.pid).count
        return VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
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
                Button {
                    if selectedSessionRoot == root.pid {
                        selectedSessionRoot = nil
                    } else {
                        selectedSessionRoot = root.pid
                    }
                    selectedProcess = root
                } label: {
                    HStack(spacing: 5) {
                        Text(root.cwdLeaf)
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(.primary)
                            .lineLimit(1).truncationMode(.middle)
                            .help(root.cwd ?? root.name)
                        Text("PID \(root.pid)")
                            .font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                        if !children.isEmpty {
                            Text("+\(children.count)")
                                .font(.system(size: 8, weight: .semibold)).foregroundStyle(.tertiary)
                        }
                        if let mem {
                            Text(mem)
                                .font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                        }
                        if let cpu {
                            Text(String(format: "%.0f%%", cpu))
                                .font(.system(size: 9, design: .monospaced))
                                .foregroundStyle(cpu >= 100 ? Color.warn : Color.secondary)
                                .help("CPU across this session's process family")
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
                if flagN > 0 {
                    Text("\(flagN)")
                        .font(.system(size: 8, weight: .bold, design: .rounded))
                        .foregroundStyle(Color.bad)
                        .help("\(flagN) unacted flag\(flagN == 1 ? "" : "s") in this session")
                }
                Button {
                    state.kill(pid: root.pid)
                } label: {
                    Image(systemName: "power")
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Color.bad)
                        .padding(4)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("Terminate this session's process tree")
            }
            .padding(.leading, insideGroup ? 12 : 0)
            .padding(.vertical, 2)
            .background(selectedSessionRoot == root.pid ? Color.brand.opacity(0.10) : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: 6))

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
                if let cpu = child.cpuPercent {
                    Text(String(format: "%.0f%%", cpu))
                        .font(.system(size: 8, design: .monospaced))
                        .foregroundStyle(cpu >= 100 ? Color.warn : Color.secondary)
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


/// One "needs attention" row: a flag group plus its newest open incident (if
/// any). Identifiable for ForEach — the group id is the identity.
private struct AttentionRow: Identifiable {
    let group: AppState.FlagGroup
    let incident: IncidentReportModel?
    var id: String { group.id }
}

@MainActor
private func attentionRows(groups: [AppState.FlagGroup], openIncidents: [IncidentReportModel]) -> [AttentionRow] {
    let incidentByFlag = Dictionary(uniqueKeysWithValues: openIncidents.map { ($0.flagId, $0) })
    return groups.map { g in
        let incident = g.flags.compactMap { incidentByFlag[$0.id] }.first
        return AttentionRow(group: g, incident: incident)
    }
}
