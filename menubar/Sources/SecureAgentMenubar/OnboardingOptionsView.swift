import SwiftUI

/// Optional capabilities remain reachable after the selected path's result.
@MainActor
struct OnboardingOptionsView: View {
    @ObservedObject var setup: SetupManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("File Telemetry") {
                ESFileTelemetryCard(setup: setup).padding(.vertical, 4)
            }
            GroupBox("Additional Harness Hooks") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Install scripts for Claude, Cursor and opencode. Interactive guard checks support Claude and Cursor; script installation does not establish runtime coverage.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Install All Harness Hook Scripts") { run { try setup.installHooks() } }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox("Extras") {
                HStack {
                    Button("Open at Login") { run { try setup.enableLoginItem() } }
                        .disabled(setup.isLoginItemEnabled)
                    Button("Install CLI Tool") { run { try setup.installCLI() } }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("Agent Routing") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Route your agents through the local inspection proxy to scan their outbound traffic for secret leaks. Opt-in and scoped to your shell — it changes no system or keychain settings.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(setup.agentRoutingSourceCommand)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(6)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Color.secondary.opacity(0.12)))
                    HStack {
                        Button("Copy Command") { setup.copyAgentRoutingCommand() }
                        Button("Show File") { setup.revealAgentRoutingSnippet() }
                            .disabled(!setup.isAgentRoutingConfigured)
                    }
                    Text("Run it in each shell where you launch agents, or add it to your shell profile (e.g. ~/.zshrc) to make it permanent.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("Secret Registry") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Register your real secrets so the firewall catches them leaking with near-zero false positives. Values are fingerprinted (HMAC) and never stored.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Scan & Register My Secrets") { Task { await setup.registerSecrets() } }
                    if setup.didRegisterSecrets {
                        if setup.registeredSecrets.isEmpty {
                            Text("No secrets found in the configured sources. Add paths under firewall.registry.ingest_sources in the config, then rescan.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        } else {
                            Text("Watching \(setup.registeredSecrets.count) secret\(setup.registeredSecrets.count == 1 ? "" : "s"):")
                                .font(.caption)
                            ForEach(setup.registeredSecrets, id: \.self) { label in
                                Text("• \(label)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("Guard Your Secrets") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Turn on the interactive guard for SSH keys, cloud credentials, the keychain, and your harness config (settings & hook scripts). When an agent reaches for one, you get a native Allow / Deny prompt. Requests can be denied, including when an approval times out. Existing policies still apply.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Guard My Secrets") { setup.enableGuardClassics() }
                        .disabled(setup.didGuardClassics)
                    if setup.didGuardClassics {
                        Text("Guarding SSH keys, cloud credentials, keychain, and harness config — you'll be prompted on first access.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("Local Advisor") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("A locally served model (MLX, llama.cpp, Ollama) triages flags and writes plain-English incident narratives — on this machine only. The daemon refuses any non-loopback endpoint, and verdicts never change enforcement.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    let discovery = setup.advisorDiscovery
                    if let m = discovery.machine {
                        Text(m.summary).font(.caption).foregroundStyle(.secondary)
                    }
                    if let r = discovery.recommended {
                        HStack(alignment: .firstTextBaseline) {
                            Image(systemName: "sparkles").foregroundStyle(.secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Recommended for this Mac: \(r.label)").font(.callout)
                                Text((r.source == "installed" ? "On your server · " : "Managed · ") + r.note)
                                    .font(.caption).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            Button("Recheck") { Task { await setup.refreshState() } }
                        }
                    } else {
                        HStack {
                            Text("No recommendation yet: the daemon is not answering.").font(.callout)
                            Spacer()
                            Button("Recheck") { Task { await setup.refreshState() } }
                        }
                    }
                    if setup.advisorEnabled {
                        Label("Advisor enabled", systemImage: "checkmark.circle.fill")
                            .font(.callout).foregroundStyle(.green)
                        Button("Disable Advisor") { setup.setAdvisorEnabled(false) }
                    } else if let r = discovery.recommended {
                        Button("Use recommended") { setup.applyRecommendation(r) }
                        Text("More models in Settings → Secure Agent.").font(.caption).foregroundStyle(.secondary)
                    }
                    if let note = setup.advisorNote {
                        Text(note).font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Divider()
                    DisclosureGroup("Timeout, classifier and debug logs") {
                        AdvisorOptionsView()
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

        }
    }

    private func run(_ action: () throws -> Void) {
        do { try action() } catch { setup.report(error) }
        Task { await setup.refreshState() }
    }
}
