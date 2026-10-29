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
                    Text("Install hook files for Claude, Cursor, Codex, OpenClaw, Antigravity, Hermes and OpenCode v2. Follow each harness's activation guidance; enable OpenClaw through its selected setup path. Manual guard checks support Claude and Cursor. Installation does not establish runtime coverage.")
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
                    Button("Set Up Traffic") { SettingsWindowController.shared.show(tab: .traffic) }
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
