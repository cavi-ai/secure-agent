import SwiftUI

/// The menu-bar popover: glance and act, nothing more. 340pt wide.
///
/// The console is the product; this surface answers "are my agents okay, and
/// does anything need me right now" and gets out of the way. Drill-downs
/// (agent sort, family trees, subagent nesting, flag/incident/process sheets)
/// live in the web console — a 340×420 popover doing a work surface's job was
/// the audited complexity. What stays: the posture hero, any collector/error
/// banner, the pending guard decision inline, up to three session cards with
/// a live heartbeat, and the one button that opens the console.
@MainActor
struct ConsoleView: View {
    @ObservedObject var state: AppState
    @ObservedObject private var supervisor = DaemonSupervisor.shared
    /// Preview/snapshot renderers don't lay out ScrollView content; set false
    /// to render the sections in a plain stack for snapshots.
    var scrollable: Bool = true

    /// How many session cards the glance shows. Three is enough to answer
    /// "what is running" without becoming a list.
    private let maxSessionCards = 3

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

    // MARK: sections

    private var sections: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let err = state.lastError { banner(err, icon: "exclamationmark.triangle.fill", tint: .warn) }
            if let notice = state.advisorNotice { advisorNoticeBanner(notice) }
            if let abandoned = state.abandonedCollectors, !abandoned.isEmpty {
                collectorBanner(abandoned)
            }
            hero
            if let pending = state.pendingGuard { guardDecisionCard(pending) }
            if !state.agentRoots.isEmpty { sessionCards }
        }
    }

    /// A shared banner row: icon, message, optional action.
    private func banner(_ message: String, icon: String, tint: Color) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon).font(.system(size: 11)).foregroundStyle(tint)
            Text(message).font(.system(size: 11)).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    /// A collector the supervisor gave up on is the honest "why are
    /// transcripts thin / is this even monitoring" answer — silence otherwise
    /// reads as working.
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

    // MARK: hero

    /// The one-glance answer, mirroring the web console's posture banner:
    /// Protected / Attention / Action needed (+ Disconnected). The hero IS the
    /// action when action is needed: tapping it opens the top flag's sheet in
    /// the console, or the egress drill-down for uninspected egress.
    private var hero: some View {
        let m = heroModel
        let actionable = m.action != nil
        return Button {
            switch m.action {
            case .flag:
                // Per-flag deep-links aren't part of the console URL protocol
                // yet; open its home tab where the row is first in the list.
                state.openDashboard(tab: "findings")
            case .openConsole(let tab):
                state.openDashboard(tab: tab)
            case nil:
                break
            }
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

    // Internal (not private) so the hero regression tests can drive it.
    var heroModel: (icon: String, color: Color, title: String, subtitle: String, action: AppState.HeroAction?) {
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
            // Prose-first: name what happened + what to do, not counts.
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
                case "allow-host": advice = "review it in the console"
                case "mute-rule": advice = "dismiss the class in the console"
                case "rotate-credentials": advice = "rotate the credential"
                case "kill-agent": advice = "stop the agent"
                default: advice = "review it in the console"
                }
                return ("exclamationmark.shield.fill", .bad, "Action needed",
                        "\(what) — \(advice).", .flag(top))
            }
            return ("exclamationmark.shield.fill", .bad, "Action needed",
                    "Review the flagged activity in the console.", nil)
        }
        // Unacted only: a flag the operator already reviewed/dismissed must
        // not keep demanding attention in the hero (the "20 flags to review"
        // that were all long-handled). Same filter as the attention section.
        let warnFlags = state.unactedFlags.count
        if warnFlags > 0 || state.uninspectedEgress > 0 || state.firewallWouldBlock > 0 {
            var parts: [String] = []
            if warnFlags > 0 { parts.append("\(warnFlags) flag\(warnFlags == 1 ? "" : "s") to review") }
            if state.firewallWouldBlock > 0 { parts.append("\(state.firewallWouldBlock) would-block") }
            if state.uninspectedEgress > 0 { parts.append("\(state.uninspectedEgress) uninspected") }
            // Every count in the subtitle is clickable: flags open the top
            // one's sheet in the console; uninspected/would-block open the
            // egress drill-down. "If I can't click it I don't wanna see it."
            let action: AppState.HeroAction?
            if let topWarn = state.unactedFlags.first {
                action = .flag(topWarn)
            } else {
                action = .openConsole(tab: "egress")
            }
            return ("exclamationmark.triangle.fill", .warn, "Attention",
                    parts.joined(separator: " · "), action)
        }
        let n = state.activeAgentCount
        let procs = state.trackedProcessCount
        let sub = procs > n
            ? "\(n) agent\(n == 1 ? "" : "s") monitored · \(procs) processes tracked · firewall \(state.isEnforcing ? "enforcing" : "monitoring")"
            : "\(n) agent\(n == 1 ? "" : "s") monitored · firewall \(state.isEnforcing ? "enforcing" : "monitoring")"
        return ("checkmark.shield.fill", .ok, "Protected", sub, nil)
    }

    // MARK: guard decision (inline consent)

    /// The pending guard decision, inline. The native NSAlert remains the
    /// always-on path (it fires even with the popover closed); when the
    /// operator has the popover open, this lets them decide without waiting on
    /// a modal. Return key is not bound here — denying stays the deliberate act.
    private func guardDecisionCard(_ p: GuardPending) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "hand.raised.fill")
                    .font(.system(size: 12)).foregroundStyle(Color.warn)
                VStack(alignment: .leading, spacing: 1) {
                    Text(Self.guardPromptHeadline(p))
                        .font(.system(size: 11, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(Self.guardPromptDetail(p))
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let scope = p.scopeText, !scope.isEmpty {
                Text("⚠️ \(scope)")
                    .font(.system(size: 10)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let advice = p.advisor {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: Self.advisorSymbol(advice.recommendation))
                        .font(.system(size: 10)).foregroundStyle(Self.advisorColor(advice.recommendation))
                    Text("Advisor: \(advice.rationale)")
                        .font(.system(size: 10)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(6)
                .background(Self.advisorColor(advice.recommendation).opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            HStack(spacing: 6) {
                Button { Task { await state.resolvePendingGuard(verdict: "allow", scope: "once") } } label: {
                    Text("Allow Once").font(.system(size: 11, weight: .semibold))
                }.buttonStyle(.bordered).controlSize(.small).tint(.brand)
                Button { Task { await state.resolvePendingGuard(verdict: "allow", scope: "always") } } label: {
                    Text("Allow Always").font(.system(size: 11))
                }.buttonStyle(.bordered).controlSize(.small)
                Button { Task { await state.resolvePendingGuard(verdict: "deny", scope: "always") } } label: {
                    Text("Deny").font(.system(size: 11, weight: .semibold))
                }.buttonStyle(.borderedProminent).controlSize(.small).tint(.bad)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.warn.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: session cards

    /// Up to three sessions with a live heartbeat. The full board, sorts and
    /// trees live in the console.
    private var sessionCards: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Sessions", trailing: "\(state.activeAgentCount)")
            let rows = state.sessionBoardRows(sortedBy: .lastActivity)
            ForEach(rows.prefix(maxSessionCards)) { row in
                sessionCard(row)
            }
            if rows.count > maxSessionCards {
                Button { state.openDashboard(tab: "sessions") } label: {
                    Text("+ \(rows.count - maxSessionCards) more — open the console")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(.secondary)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
    }

    /// One session card: harness glyph, project@branch-ish label, elapsed,
    /// memory, a heartbeat that actually moves, and terminate. Tapping opens
    /// the session's trace in the console.
    private func sessionCard(_ row: AppState.AgentRow) -> some View {
        let agent = row.agent
        let rss = row.familyRSSBytes.flatMap(ByteCount.short)
        let seen = relativeTime(row.familyLastSeenAt ?? agent.lastSeenAt ?? "")
        let working = seen?.hasSuffix("s") ?? false
        return HStack(spacing: 8) {
            AgentIdentity.tile(agent.name, size: 18, fontSize: 9)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    Text(agent.cwdLeaf)
                        .font(.system(size: 12, weight: .semibold))
                        .lineLimit(1).truncationMode(.middle)
                    HeartbeatDot(active: working)
                }
                HStack(spacing: 6) {
                    Text(agent.name).font(.system(size: 9)).foregroundStyle(.secondary)
                    if !agent.repoBranch.isEmpty {
                        Text(agent.repoBranch).font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    if let seen { Text(seen).font(.system(size: 9, design: .monospaced)).foregroundStyle(working ? Color.ok : Color.tertiaryText) }
                    if let rss { Text(rss).font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary) }
                    if agent.isOrphanLike {
                        Image(systemName: "questionmark.square").font(.system(size: 8)).foregroundStyle(Color.warn)
                            .help("parent already exited")
                    }
                }
            }
            Spacer(minLength: 0)
            Button { state.kill(pid: agent.pid) } label: {
                Image(systemName: "power")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Color.bad)
                    .padding(4)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Terminate this session's process tree")
        }
        .padding(8)
        .background(Color.primary.opacity(0.03))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .contentShape(Rectangle())
        .onTapGesture { state.openDashboard(tab: "sessions") }
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
                }
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 11)
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
                Button { openConsoleTapped() } label: {
                    if state.isEnablingConsole {
                        Label("Enabling…", systemImage: "hourglass").font(.system(size: 12, weight: .semibold))
                    } else {
                        Label("Open console", systemImage: "square.grid.2x2").font(.system(size: 12, weight: .semibold))
                    }
                }
                .buttonStyle(.borderedProminent).tint(.brand).controlSize(.regular)
                .disabled(!state.connected || state.isEnablingConsole)
                .help(consoleButtonHelp)
                .confirmationDialog(
                    "Turn on the local console?",
                    isPresented: $confirmEnableConsole,
                    titleVisibility: .visible
                ) {
                    Button("Turn on & open") { state.enableConsoleAndOpen() }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("The console is served by the loopback inspection proxy (127.0.0.1) — it also inspects agent egress for secret leaks, in monitor mode (nothing is blocked). Turning it on restarts the background monitor for a second.")
                }
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

    @State private var confirmEnableConsole = false

    /// "Open console" click: opens when the console is up; when it's off, the
    /// button is the way OUT of the off state (confirmation → one-click
    /// enable), not a dead greyed-out control with a tooltip.
    private func openConsoleTapped() {
        if state.dashboardUnavailableReason == nil {
            state.openDashboard()
        } else if state.connected {
            confirmEnableConsole = true
        }
    }

    private var consoleButtonHelp: String {
        if !state.connected { return "The daemon is not running" }
        if state.dashboardUnavailableReason != nil {
            return "The console is off — click to turn it on"
        }
        return "Open the web console"
    }

    private func sectionHeader(_ title: String, trailing: String) -> some View {
        HStack {
            Text(title.uppercased()).font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary).kerning(0.5)
            Spacer()
            Text(trailing).font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(.secondary)
        }
    }

    // MARK: guard prompt language

    /// Plain-language headline: what is this file, and who wants it.
    static func guardPromptHeadline(_ p: GuardPending) -> String {
        switch p.ruleID {
        case "ssh-keys": return "\(p.agent.capitalized) wants to read an SSH private key"
        case "cloud-creds": return "\(p.agent.capitalized) wants to read a cloud credential file"
        case "keychain": return "\(p.agent.capitalized) wants to touch your keychain"
        case "env-files": return "\(p.agent.capitalized) wants to read an environment file (secrets inside)"
        case "shell-rc": return "\(p.agent.capitalized) wants to access a shell config file"
        default: return "Allow \(p.agent) to access this?"
        }
    }

    /// Detail line: the concrete file, why it matters, what is being asked.
    static func guardPromptDetail(_ p: GuardPending) -> String {
        let file = (p.path as NSString).lastPathComponent
        switch p.ruleID {
        case "ssh-keys": return "\(file) — private keys grant server access; leaking one is a full compromise."
        case "cloud-creds": return "\(file) — cloud credentials can be used from anywhere once leaked."
        case "keychain": return "\(file) — the keychain holds saved passwords and tokens."
        case "env-files": return "\(file) — environment files often carry API keys and database passwords."
        case "shell-rc": return "\(file) — shell config runs on every new terminal."
        default: return "\(file)"
        }
    }

    /// Advisor recommendation → symbol/color. "allow" reads green, "deny" red,
    /// "look" amber — matching the chip vocabulary the console uses.
    static func advisorSymbol(_ recommendation: String) -> String {
        switch recommendation {
        case "allow": return "checkmark.circle"
        case "deny": return "xmark.octagon"
        default: return "questionmark.circle"
        }
    }

    static func advisorColor(_ recommendation: String) -> Color {
        switch recommendation {
        case "allow": return .ok
        case "deny": return .bad
        default: return .warn
        }
    }
}

/// A small dot that breathes while a session is working — motion that carries
/// meaning, and respects reduced motion.
private struct HeartbeatDot: View {
    let active: Bool

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Circle()
            .fill(active ? Color.ok : Color.secondary.opacity(0.5))
            .frame(width: 6, height: 6)
            .opacity(active && !reduceMotion ? 1 : 0.75)
            .scaleEffect(active && !reduceMotion ? 1.0 : 0.85)
            .animation(
                active && !reduceMotion
                    ? .easeInOut(duration: 1.2).repeatForever(autoreverses: true)
                    : .default,
                value: active
            )
            .help(active ? "Working — activity in the last minute" : "Idle")
    }
}
