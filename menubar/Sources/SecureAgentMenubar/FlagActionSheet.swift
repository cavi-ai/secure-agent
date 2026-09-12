import SwiftUI

/// Flag detail + actions: a critical is a decision point, not a read-only
/// notice. Shows the full evidence chain, links to the incident report when
/// one exists, and offers the dispositions that make sense for the flag
/// class — mute this rule+host (noise control), allow the host, kill the
/// agent. Same consequence-disclosure discipline as the incident sheet.
@MainActor
struct FlagActionSheet: View {
    let flag: FlagModel
    var state: AppState
    @State private var incident: IncidentReportModel?
    @State private var applied: String?
    @State private var failure: String?
    /// The action awaiting its confirmation (nil = none pending).
    @State private var confirming: PendingAction?
    @State private var showIncident = false
    @Environment(\.dismiss) private var dismiss

    /// One pending decision with its server call.
    struct PendingAction: Identifiable {
        let id = UUID()
        let title: String
        let message: String
        let buttonLabel: String
        let destructive: Bool
        let fire: () async throws -> Void
        let doneLabel: String
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let applied { appliedBanner(applied) }
                    if let failure { failureBanner(failure) }
                    evidenceBlock
                    actions
                }
                .padding(14)
            }
            Divider()
            footer
        }
        .frame(width: 500, height: 440)
        .task { await loadIncident() }
        .sheet(isPresented: $showIncident) {
            if let incident { IncidentDetailView(incident: incident, state: state) }
        }
        .confirmationDialog(
            confirming?.title ?? "",
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            titleVisibility: .visible
        ) {
            Button(confirming?.buttonLabel ?? "OK",
                   role: confirming?.destructive == true ? .destructive : nil) {
                Task { await runPending() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(confirming?.message ?? "")
        }
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: flag.severity >= 3 ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(flag.severity >= 3 ? Color.bad : Color.warn)
                .frame(width: 34, height: 34)
                .background((flag.severity >= 3 ? Color.bad : Color.warn).opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 2) {
                Text(Self.humanTitle(flag.rule))
                    .font(.system(size: 14, weight: .bold))
                HStack(spacing: 8) {
                    AgentIdentity.tile(flag.agent, size: 16)
                    Text(flag.agent).font(.system(size: 11, weight: .medium))
                    Text("PID \(flag.pid)")
                        .font(.system(size: 9, design: .monospaced)).foregroundStyle(.tertiary)
                    if let t = relativeTime(flag.ts) {
                        Text(t)
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .help(absoluteTime(flag.ts))
                    }
                }
            }
            Spacer()
            Button("Done") { dismiss() }
                .keyboardShortcut(.cancelAction)
        }
        .padding(14)
    }

    /// Rule → operator language (third copy of this table; mirrors
    /// NotificationManager + posture.go until a shared table lands).
    nonisolated static func humanTitle(_ rule: String) -> String {
        switch rule {
        case "sensitive-read-then-connect": return "Agent read a secret, then connected out"
        case "proxy-secret-leak": return "Secret left in agent traffic"
        case "keychain-access": return "Agent touched your keychain"
        case "keychain-security-cli": return "Agent ran the keychain tool"
        case "tcc-tamper": return "Agent modified privacy permissions"
        case "proxy-prompt-injection": return "Prompt injection in a response"
        default: return rule
        }
    }

    // MARK: evidence

    private var evidenceBlock: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("EVIDENCE")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)
                .kerning(0.5)
            ForEach(Array(flag.evidence.prefix(6).enumerated()), id: \.offset) { _, ev in
                HStack(alignment: .top, spacing: 6) {
                    Text(relativeTime(Self.timestampIn(ev)) ?? "·")
                        .font(.system(size: 9, weight: .medium, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .frame(width: 30, alignment: .trailing)
                    Text(ev)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if flag.evidence.count > 6 {
                Text("+ \(flag.evidence.count - 6) more lines")
                    .font(.system(size: 9)).foregroundStyle(.tertiary)
            }
            if let sid = flag.sessionId, !sid.isEmpty {
                Label("session \(sid.prefix(8))", systemImage: "link")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.quaternary)
            }
            if let v = flag.advisor, !v.rationale.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 6) {
                        Image(systemName: "brain")
                            .font(.system(size: 10)).foregroundStyle(Color.brand)
                        Text("ADVISOR READ")
                            .font(.system(size: 9, weight: .semibold))
                            .kerning(0.5)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text("\(v.assessment) · \(v.confidence.map { Int($0 * 100) } ?? 0)%")
                            .font(.system(size: 9, weight: .semibold, design: .rounded))
                            .foregroundStyle(v.assessment == "benign" ? Color.ok : (v.assessment == "malicious" ? Color.bad : Color.warn))
                    }
                    Text(v.rationale)
                        .font(.system(size: 11))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(10)
                .background(Color.primary.opacity(0.03))
                .clipShape(RoundedRectangle(cornerRadius: 7))
            }
        }
    }

    /// Evidence lines end in "at <RFC3339>" — the per-row time rail source.
    nonisolated static func timestampIn(_ line: String) -> String {
        guard let at = line.range(of: " at "), at.upperBound < line.endIndex else { return "" }
        return String(line[at.upperBound...])
    }

    // MARK: actions

    /// The primary host in the evidence (disposition target), nil if none.
    nonisolated static func hostIn(evidence: [String]) -> String? {
        for line in evidence {
            guard let to = line.range(of: "connected to "),
                  let at = line[to.upperBound...].range(of: " at ") else { continue }
            let hostPort = String(line[to.upperBound..<at.lowerBound])
            let h = hostFromHostPort(hostPort)
            if !h.isEmpty { return h }
        }
        return nil
    }

    nonisolated static func hostFromHostPort(_ s: String) -> String {
        if s.hasPrefix("["), let end = s.firstIndex(of: "]") {
            return String(s[s.index(after: s.startIndex)..<end])
        }
        if let colon = s.lastIndex(of: ":") {
            let host = s[..<colon]
            if !host.contains(":") { return String(host) }
        }
        return s
    }

    private var evidenceHost: String? { Self.hostIn(evidence: flag.evidence) }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("WHAT TO DO")
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)
                .kerning(0.5)

            // Re-triage: re-run the advisor for a fresh verdict (idempotent
            // server-side — 30s cooldown per flag; the stored verdict is
            // overwritten on completion). Shown so flags triaged under the
            // older free-form prompt can be upgraded to actionable ones.
            actionRow(
                icon: "arrow.triangle.2.circlepath", tint: Color.brand,
                title: "Re-run the advisor",
                subtitle: "Ask the local model to re-read this flag and produce a fresh recommendation. Safe to click repeatedly.",
                pending: PendingAction(
                    title: "Re-run the advisor?",
                    message: "The local model re-reads this flag and replaces its recommendation. Takes a few seconds.",
                    buttonLabel: "Re-run", destructive: false,
                    fire: { try await state.uiClient.retriageFlag(id: flag.id) },
                    doneLabel: "advisor re-running — the recommendation updates automatically")) {}

            // Advisor's recommendation leads — with an Apply button that
            // actually executes it. "There's an action" now means a button.
            if let rec = Self.mappedAction(flag.advisor?.suggestedAction,
                                           flag: flag,
                                           evidenceHost: evidenceHost) {
                advisorActionRow(rec)
            }

            if incident != nil {
                actionRow(
                    icon: "cross.case.fill", tint: Color.bad,
                    title: "Open incident report",
                    subtitle: "The full remediation checklist with rotation advice.",
                    pending: nil) {
                    showIncident = true
                }
            }
            if let host = evidenceHost {
                actionRow(
                    icon: "checkmark.circle", tint: Color.ok,
                    title: "Allow \(host) for \(flag.agent)",
                    subtitle: "Future connections to this host are trusted and stop being flagged.",
                    pending: PendingAction(
                        title: "Trust \(host)?",
                        message: "Future connections from \(flag.agent) to \(host) are trusted and stop being flagged.",
                        buttonLabel: "Allow host", destructive: false,
                        fire: { try await state.uiClient.allowlistAdd(agent: flag.agent, host: host) },
                        doneLabel: "\(host) allowlisted — this pair stops flagging")) {}
            }
            if let host = evidenceHost {
                actionRow(
                    icon: "eye.slash", tint: Color.warn,
                    title: "Dismiss this flag class",
                    subtitle: "Stop flagging \(Self.humanTitle(flag.rule).lowercased()) against \(host). The host stays monitored.",
                    pending: PendingAction(
                        title: "Dismiss future flags of this kind?",
                        message: "\(flag.rule) keeps monitoring \(host), but stops flagging incidents like this one against it.",
                        buttonLabel: "Dismiss", destructive: false,
                        fire: { try await state.uiClient.muteAdd(rule: flag.rule, host: host) },
                        doneLabel: "dismissed — future flags of this rule for \(host) are suppressed")) {}
            }
            actionRow(
                icon: "power", tint: Color.bad,
                title: "Kill \(flag.agent) (pid \(flag.pid))",
                subtitle: "Terminate the agent process tree now. Unsaved work is lost.",
                pending: PendingAction(
                    title: "Kill this agent?",
                    message: "The agent process tree is terminated immediately. Unsaved work in it is lost.",
                    buttonLabel: "Kill agent", destructive: true,
                    fire: { _ = try await state.uiClient.killProcess(pid: flag.pid) },
                    doneLabel: "agent terminated")) {}
        }
    }

    /// The advisor's suggested_action mapped to an executable disposition —
    /// when the advisor has an opinion, ITS action leads the list with an
    /// Apply button. Pure mapping, unit-testable.
    nonisolated static func mappedAction(_ suggested: String?, flag: FlagModel, evidenceHost: String?) -> (title: String, subtitle: String, kind: String)? {
        switch suggested {
        case "allow-host":
            guard let h = evidenceHost, !h.isEmpty else { return nil }
            return ("Allow \(h) for \(flag.agent)",
                    "The advisor assessed this host as legitimate. Future connections to it stop being flagged.",
                    "allow-host")
        case "mute-rule":
            return ("Dismiss this flag class",
                    "Stop flagging this in this context. Monitoring continues.",
                    "mute-rule")
        case "rotate-credentials":
            return ("Rotate the exposed credential",
                    "The advisor believes a secret may have left the machine. Opens the remediation checklist with the rotation steps.",
                    "rotate")
        case "kill-agent":
            return ("Kill \(flag.agent) (pid \(flag.pid))",
                    "The advisor judged the agent's behavior the problem. Terminates the process tree now.",
                    "kill")
        default:
            return nil
        }
    }

    /// The advisor's recommendation as a first-class action row with an
    /// Apply button wired to the mapped endpoint.
    @State private var applyingAdvisor = false
    private func advisorActionRow(_ rec: (title: String, subtitle: String, kind: String)) -> some View {
        return HStack(spacing: 8) {
            Image(systemName: "brain")
                .font(.system(size: 11)).foregroundStyle(Color.brand)
                .frame(width: 22, height: 22)
                .background(Color.brand.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 5))
            VStack(alignment: .leading, spacing: 1) {
                Text(rec.title).font(.system(size: 11, weight: .semibold))
                Text(rec.subtitle)
                    .font(.system(size: 9)).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Button {
                applyingAdvisor = true
                Task {
                    await executeMapped(rec.kind)
                    applyingAdvisor = false
                }
            } label: {
                if applyingAdvisor {
                    ProgressView().controlSize(.mini)
                } else {
                    Text("Apply").font(.system(size: 10, weight: .semibold))
                }
            }
            .buttonStyle(.borderedProminent).tint(Color.brand).controlSize(.small)
            .disabled(applyingAdvisor)
        }
        .padding(8)
        .background(Color.brand.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 7))
    }

    private func executeMapped(_ kind: String) async {
        do {
            switch kind {
            case "allow-host":
                guard let host = evidenceHost else { return }
                try await state.uiClient.allowlistAdd(agent: flag.agent, host: host)
                applied = "\(host) allowlisted — this pair stops flagging"
            case "mute-rule":
                guard let host = evidenceHost else { return }
                try await state.uiClient.muteAdd(rule: flag.rule, host: host)
                applied = "dismissed — future flags of this rule are suppressed"
            case "rotate":
                if let incident = state.incidents.first(where: { $0.flagId == flag.id }) {
                    showIncident = true
                    applied = "opened the rotation checklist"
                } else {
                    applied = "open the incident report for rotation steps"
                }
            case "kill":
                _ = try await state.uiClient.killProcess(pid: flag.pid)
                applied = "agent terminated"
            default:
                return
            }
            state.refresh()
        } catch {
            failure = error.localizedDescription
        }
    }

    private func actionRow(
        icon: String, tint: Color, title: String, subtitle: String,
        pending: PendingAction?, fire: @escaping () -> Void
    ) -> some View {
        Button {
            if let pending { confirming = pending } else { fire() }
        } label: {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 11)).foregroundStyle(tint)
                    .frame(width: 22, height: 22)
                    .background(tint.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 5))
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(.system(size: 11, weight: .semibold))
                    Text(subtitle)
                        .font(.system(size: 9)).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.system(size: 8, weight: .semibold)).foregroundStyle(.quaternary)
            }
            .padding(8)
            .background(Color.primary.opacity(0.03))
            .clipShape(RoundedRectangle(cornerRadius: 7))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    // MARK: effects

    private func loadIncident() async {
        // The correlator generates one incident per critical flag; find it
        // by flag id. Absent = flag predates incidents or is non-incident
        // class — the sheet still works, just without the checklist link.
        incident = state.incidents.first { $0.flagId == flag.id }
    }

    private func runPending() async {
        guard let pending = confirming else { return }
        confirming = nil
        do {
            try await pending.fire()
            applied = pending.doneLabel
            state.refresh()
        } catch {
            failure = error.localizedDescription
        }
    }

    private func appliedBanner(_ label: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.ok)
            Text(label).font(.system(size: 11, weight: .medium))
            Spacer()
        }
        .padding(10)
        .background(Color.ok.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func failureBanner(_ message: String) -> some View {
        Label(message, systemImage: "xmark.octagon")
            .font(.system(size: 11))
            .foregroundStyle(Color.bad)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.bad.opacity(0.10))
            .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var footer: some View {
        HStack {
            if incident != nil {
                Button { showIncident = true } label: {
                    Label("Incident report", systemImage: "cross.case")
                        .font(.system(size: 10, weight: .medium))
                }
                .buttonStyle(.bordered).controlSize(.small)
            }
            Spacer()
            Button("Close") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }
}