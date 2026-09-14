import SwiftUI

/// Incident detail sheet. Redesigned: the raw markdown the daemon generates
/// is written for an agent/audit trail — a user glancing at a critical flag
/// needs the *answer* first (what happened, what do I do), with structured
/// evidence rows and dispositions. The raw report stays available behind a
/// disclosure with one-click copy (for handing to an agent).
@MainActor
struct IncidentDetailView: View {
    let incident: IncidentReportModel
    var state: AppState
    @State private var markdown: String?
    @State private var loadError: String?
    @State private var appliedDisposition: String?
    @State private var dispositionError: String?
    @State private var copiedRaw = false
    @State private var showRaw = false
    /// The disposition awaiting its confirmation dialog (nil = none).
    @State private var confirming: DispositionKind?
    @Environment(\.dismiss) private var dismiss

    // MARK: disposition model

    /// The decisions that make sense for this class of incident
    /// (Little-Snitch model: see the infraction, rule on it, never see it
    /// again). Host-targeted ones exist only when connections exist.
    enum DispositionKind: String, Identifiable, CaseIterable {
        case allowHost
        case pathAllow
        case muteRuleHost
        case killAgent

        var id: String { rawValue }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let applied = appliedDisposition {
                        appliedBanner
                    }
                    if let dispositionError {
                        dispositionErrorView
                    }
                    whatHappened
                    if !incident.touchedFiles.isEmpty { evidenceFiles }
                    if !incident.connections.isEmpty { evidenceConnections }
                    dispositions
                    rawDisclosure
                }
                .padding(14)
            }
            Divider()
            footer
        }
        .frame(width: 520, height: 500)
        .task {
            do {
                markdown = try await state.uiClient.fetchIncidentMarkdown(id: incident.id)
            } catch {
                loadError = error.localizedDescription
            }
        }
        .confirmationDialog(
            confirmTitle,
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            titleVisibility: .visible
        ) {
            Button(confirmActionTitle, role: confirming == .killAgent ? .destructive : nil) {
                Task { await applyDisposition(confirming ?? .killAgent) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(confirmMessage)
        }
    }

    private var confirmTitle: String {
        switch confirming {
        case .allowHost: return "Trust this host?"
        case .pathAllow: return "Allow this file?"
        case .muteRuleHost: return "Mute these flags?"
        case .killAgent: return "Kill this agent?"
        case nil: return ""
        }
    }

    private var confirmActionTitle: String {
        switch confirming {
        case .allowHost: return "Allow host"
        case .pathAllow: return "Allow file"
        case .muteRuleHost: return "Mute"
        case .killAgent: return "Kill agent"
        case nil: return ""
        }
    }

    private var confirmMessage: String {
        switch confirming {
        case .allowHost: return "Future connections from \(incident.agent) to \(host ?? "") are trusted and stop being flagged."
        case .pathAllow: return "\(incident.agent) may access \(primaryFilePath ?? "this file") (and anything inside it) without prompting — other sensitive paths under this rule still require approval."
        case .muteRuleHost: return "This rule keeps monitoring \(host ?? "the host"), but stops flagging incidents like this one against it."
        case .killAgent: return "The agent process tree is terminated immediately. Unsaved work in it is lost."
        case nil: return ""
        }
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: "cross.case.fill")
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(Color.bad)
                .frame(width: 34, height: 34)
                .background(Color.bad.opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 1) {
                Text(humanTitle)
                    .font(.system(size: 14, weight: .bold))
                HStack(spacing: 6) {
                    Text(incident.agent).font(.system(size: 11, weight: .medium))
                    Text("PID \(incident.pid)")
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.tertiary)
                    if let seen = relativeTime(incident.timestamp) {
                        Text(seen)
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .help(absoluteTime(incident.timestamp))
                    }
                }
            }
            Spacer()
            Text(incident.risk.uppercased())
                .font(.system(size: 9, weight: .bold))
                .foregroundStyle(Color.bad)
                .padding(.horizontal, 7).padding(.vertical, 4)
                .background(Color.bad.opacity(0.14))
                .clipShape(Capsule())
            Button("Done") { dismiss() }
                .keyboardShortcut(.cancelAction)
        }
        .padding(14)
    }

    /// Rule → operator language. Mirrors NotificationManager's table and the
    /// daemon's posture.go — three copies until a shared table lands.
    private var humanTitle: String {
        switch incident.rule {
        case "sensitive-read-then-connect": return "Agent read a secret, then connected out"
        case "proxy-secret-leak": return "Secret left in agent traffic"
        case "keychain-access": return "Agent touched your keychain"
        case "keychain-security-cli": return "Agent ran the keychain tool"
        case "tcc-tamper": return "Agent modified privacy permissions"
        case "proxy-prompt-injection": return "Prompt injection in a response"
        default: return incident.rule
        }
    }

    // MARK: what happened

    /// The daemon-written summary is the narrative answer; render it as the
    /// primary block instead of the markdown checklist wall.
    private var whatHappened: some View {
        VStack(alignment: .leading, spacing: 6) {
            sectionLabel("What happened")
            Text(incident.summary)
                .font(.system(size: 12))
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
    }

    // MARK: evidence

    private var evidenceFiles: some View {
        VStack(alignment: .leading, spacing: 4) {
            evidenceHeader("Files touched", count: incident.touchedFiles.count)
            ForEach(Array(incident.touchedFiles.prefix(6).enumerated()), id: \.offset) { _, f in
                HStack(spacing: 6) {
                    Image(systemName: "doc")
                        .font(.system(size: 9)).foregroundStyle(.secondary)
                    Text(Self.filePathOnly(from: f))
                        .font(.system(size: 10, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.head)
                        .help(f)
                    Spacer(minLength: 0)
                }
            }
            if incident.touchedFiles.count > 6 {
                Text("+ \(incident.touchedFiles.count - 6) more (full list in raw report)")
                    .font(.system(size: 9)).foregroundStyle(.tertiary)
            }
        }
    }

    private var evidenceConnections: some View {
        VStack(alignment: .leading, spacing: 4) {
            evidenceHeader("Connections", count: incident.connections.count)
            ForEach(Array(incident.connections.prefix(6).enumerated()), id: \.offset) { _, c in
                HStack(spacing: 6) {
                    Image(systemName: "network")
                        .font(.system(size: 9)).foregroundStyle(.secondary)
                    Text(Self.connHostPort(from: c))
                        .font(.system(size: 10, design: .monospaced))
                        .lineLimit(1)
                        .help(c)
                    Spacer(minLength: 0)
                    // The Little-Snitch affordance, inline: allow this host.
                    if !Self.host(from: c).isEmpty {
                        Button("Allow") { Task { await applyDisposition(.allowHost) } }
                            .font(.system(size: 9, weight: .semibold))
                            .buttonStyle(.bordered).controlSize(.mini).tint(Color.brand)
                            .help("Allowlist \(Self.host(from: c)) for \(incident.agent) — this pair stops being flagged")
                    }
                }
            }
        }
    }

    private func evidenceHeader(_ title: String, count: Int) -> some View {
        HStack {
            Text(title.uppercased())
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.secondary)
                .kerning(0.5)
            Text("\(count)")
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .foregroundStyle(.tertiary)
            Spacer()
        }
    }

    // MARK: dispositions

    /// The decisions that make sense for a critical read-then-connect class:
    /// allow the host (trusted endpoint), mute this rule+host pair (stop the
    /// noise), or kill the agent (unacceptable). Each states its consequence —
    /// a disposition is consent only if you know what you just approved.
    private var dispositions: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionLabel("Do something about it")

            if let host {
                dispositionRow(
                    icon: "checkmark.circle", tint: Color.ok,
                    title: "Allow \(host) for \(incident.agent)",
                    subtitle: "Future connections to this host are trusted and stop being flagged.",
                    kind: .allowHost)
                dispositionRow(
                    icon: "checkmark.seal", tint: Color.brand,
                    title: "Always allow \(primaryFilePathBasename)",
                    subtitle: "This exact file (and its contents) stops requiring approval for \(incident.agent). The rule stays.",
                    kind: .pathAllow)
                dispositionRow(
                    icon: "eye.slash", tint: Color.warn,
                    title: "Mute this flag for \(host)",
                    subtitle: "Keep monitoring the host, but stop flagging \(incident.rule) against it.",
                    kind: .muteRuleHost)
            }
            dispositionRow(
                icon: "power", tint: Color.bad,
                title: "Kill \(incident.agent) (pid \(incident.pid))",
                subtitle: "Terminate the agent process tree now. Unsaved work in it is lost.",
                kind: .killAgent)
        }
    }

    /// The primary file path from the incident's evidence — the target of a
    /// per-path allow. First touched file that is an absolute path.
    private var primaryFilePath: String? {
        incident.touchedFiles.first { $0.hasPrefix("/") }
    }

    private var primaryFilePathBasename: String {
        guard let p = primaryFilePath else { return "this file" }
        return (p as NSString).lastPathComponent
    }

    /// The host this incident's connections converge on — the disposition
    /// target. Nil for file-only incidents.
    private var host: String? {
        incident.connections.first { !Self.connHostPort(from: $0).isEmpty }
            .flatMap { Self.host(from: $0) }
    }

    private func dispositionRow(
        icon: String, tint: Color, title: String, subtitle: String, kind: DispositionKind
    ) -> some View {
        Button {
            confirming = kind
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

    private func applyDisposition(_ kind: DispositionKind) async {
        do {
            switch kind {
            case .allowHost:
                guard let host else { return }
                try await state.uiClient.allowlistAdd(agent: incident.agent, host: host)
            case .pathAllow:
                guard let p = primaryFilePath else { return }
                try await state.uiClient.guardPathAllowAdd(agent: incident.agent, ruleID: incident.rule, path: p)
            case .muteRuleHost:
                guard let host else { return }
                try await state.uiClient.muteAdd(rule: incident.rule, host: host)
            case .killAgent:
                _ = try await state.uiClient.killProcess(pid: incident.pid)
            }
            appliedDisposition = dispositionDoneLabel(kind)
        } catch {
            dispositionError = error.localizedDescription
        }
        state.refresh()
    }

    private func dispositionDoneLabel(_ kind: DispositionKind) -> String {
        switch kind {
        case .allowHost: return "host allowlisted — this pair stops flagging"
        case .pathAllow: return "\(primaryFilePathBasename) allowlisted for \(incident.agent) — no more prompts for it"
        case .muteRuleHost: return "muted — future flags of this rule for this host are suppressed"
        case .killAgent: return "agent terminated"
        }
    }

    private var appliedBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(Color.ok)
            Text("Done: \(appliedDisposition ?? "")")
                .font(.system(size: 11, weight: .medium))
            Spacer()
        }
        .padding(10)
        .background(Color.ok.opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var dispositionErrorView: some View {
        Label("Failed: \(dispositionError ?? "")", systemImage: "xmark.octagon")
            .font(.system(size: 11))
            .foregroundStyle(Color.bad)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.bad.opacity(0.10))
            .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    // MARK: raw report (the agent artifact, demoted)

    private var rawDisclosure: some View {
        DisclosureGroup(isExpanded: $showRaw) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Generated remediation report (for pasting to an agent)")
                        .font(.system(size: 9)).foregroundStyle(.tertiary)
                    Spacer()
                    Button {
                        if let markdown {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(markdown, forType: .string)
                        }
                        copiedRaw = true
                    } label: {
                        Label(copiedRaw ? "Copied" : "Copy", systemImage: copiedRaw ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 10, weight: .medium))
                    }
                    .buttonStyle(.bordered).controlSize(.mini)
                    .disabled(markdown == nil)
                }
                ScrollView {
                    Text(markdown ?? loadError.map { "Could not load report: \($0)" } ?? "Loading report…")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 160)
                .background(Color.primary.opacity(0.04))
                .clipShape(RoundedRectangle(cornerRadius: 6))
            }
            .padding(.top, 6)
        } label: {
            Label("Raw report", systemImage: "text.justify.leading")
                .font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary)
        }
    }

    // MARK: shared

    private var footer: some View {
        HStack {
            Button { state.openDashboard() } label: {
                Label("Full console", systemImage: "square.grid.2x2")
                    .font(.system(size: 10, weight: .medium))
            }
            .buttonStyle(.bordered).controlSize(.small)
            Spacer()
            Button("Close") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private func sectionLabel(_ title: String) -> some View {
        Text(title.uppercased())
            .font(.system(size: 9, weight: .semibold))
            .foregroundStyle(.secondary)
            .kerning(0.5)
    }

    // MARK: evidence parsing (pure, testable)

    /// Evidence lines look like "claude (pid 123) read /a/b at 2026-…T…" —
    /// the path is what's between "read " and " at ".
    nonisolated static func filePathOnly(from line: String) -> String {
        guard let read = line.range(of: "read "),
              let at = line[read.upperBound...].range(of: " at ") else {
            return line
        }
        return String(line[read.upperBound..<at.lowerBound])
    }

    /// "then connected to host:port at …" → "host:port"; bare "host:port" rows
    /// pass through. IPv6 bracket-aware on extraction.
    nonisolated static func connHostPort(from line: String) -> String {
        guard let to = line.range(of: "connected to "),
              let at = line[to.upperBound...].range(of: " at ") else {
            return line
        }
        return String(line[to.upperBound..<at.lowerBound])
    }

    /// "host:port" → "host"; "[::1]:443" → "::1". Bare-IPv6 returned as-is.
    nonisolated static func host(from hostPort: String) -> String {
        if hostPort.hasPrefix("["), let end = hostPort.firstIndex(of: "]") {
            return String(hostPort[hostPort.index(after: hostPort.startIndex)..<end])
        }
        if let colon = hostPort.lastIndex(of: ":") {
            let host = hostPort[..<colon]
            if !host.contains(":") { return String(host) }
        }
        return hostPort
    }
}
