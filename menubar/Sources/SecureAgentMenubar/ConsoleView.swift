import SwiftUI

private extension Color {
    static let brand = Color(.sRGB, red: 0.52, green: 0.44, blue: 0.97, opacity: 1)
    static let ok = Color(.sRGB, red: 0.30, green: 0.80, blue: 0.55, opacity: 1)
    static let warn = Color(.sRGB, red: 0.96, green: 0.62, blue: 0.20, opacity: 1)
    static let bad = Color(.sRGB, red: 0.92, green: 0.35, blue: 0.45, opacity: 1)
}

/// The menu-bar popover: a compact, premium mini-console. Deep views (full
/// history, incident reports, rotation) live in the web console via "Open console".
struct ConsoleView: View {
    @ObservedObject var state: AppState
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
            firewallSection
            guardSection
            if !state.activeAgents.isEmpty { agentsSection }
            if !state.flags.isEmpty { flagsSection }
        }
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
                          trailingColor: state.isEnforcing ? .ok : .secondary)

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
                ForEach(state.firewallRules) { rule in
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

    // MARK: guard

    private var guardSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader("Directory guard", trailing: "\(state.guardRules.count)")

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
                    Button(role: .destructive) { state.kill(pid: agent.pid) } label: {
                        Label("Kill", systemImage: "power").font(.system(size: 11, weight: .semibold))
                    }
                    .buttonStyle(.bordered).controlSize(.small)
                }
            }
        }
    }

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
        HStack(spacing: 8) {
            Button { state.openDashboard() } label: {
                Label("Open console", systemImage: "square.grid.2x2").font(.system(size: 12, weight: .semibold))
            }
            .buttonStyle(.borderedProminent).tint(.brand).controlSize(.regular)
            Spacer()
            Button { state.togglePause() } label: {
                Image(systemName: state.isPaused ? "play.circle" : "pause.circle").font(.system(size: 14))
            }.buttonStyle(.borderless).help(state.isPaused ? "Resume monitoring" : "Pause monitoring")
            Button { state.refresh() } label: {
                Image(systemName: "arrow.clockwise").font(.system(size: 13))
            }.buttonStyle(.borderless).help("Refresh")
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private func sectionHeader(_ title: String, trailing: String, trailingColor: Color = .secondary) -> some View {
        HStack {
            Text(title.uppercased()).font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary).kerning(0.5)
            Spacer()
            Text(trailing).font(.system(size: 10, weight: .semibold, design: title.contains("firewall") ? .default : .monospaced))
                .foregroundStyle(trailingColor)
        }
    }
}
