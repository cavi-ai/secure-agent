import AppKit
import SwiftUI

/// First-run setup wizard shown when the daemon isn't installed or reachable.
@MainActor
public final class OnboardingWindowController: NSObject, NSWindowDelegate {
    public static let shared = OnboardingWindowController()

    private var window: NSWindow?

    public func show() {
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let view = OnboardingView(onDone: { [weak self] in self?.close() })
        let hosting = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: hosting)
        window.title = "Secure Agent Setup"
        window.styleMask = [.titled, .closable]
        window.setContentSize(NSSize(width: 480, height: 600))
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self
        self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Auto-show the wizard at most once; afterwards it's only reachable
    /// via the "Setup & Permissions…" menu item.
    public func showOnceIfNeeded() {
        guard !UserDefaults.standard.bool(forKey: "setupWizardDismissed") else { return }
        show()
    }

    public func close() {
        UserDefaults.standard.set(true, forKey: "setupWizardDismissed")
        window?.close()
        window = nil
    }

    public func windowWillClose(_ notification: Notification) {
        UserDefaults.standard.set(true, forKey: "setupWizardDismissed")
        window = nil
    }
}

struct OnboardingView: View {
    @ObservedObject private var setup = SetupManager.shared
    var onDone: () -> Void

    var body: some View {
        VStack(spacing: 0) {
          ScrollView {
            VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "shield.fill")
                    .font(.system(size: 40))
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading) {
                    Text("Secure Agent Setup").font(.title2).bold()
                    Text("AI-agent security monitor for macOS")
                        .foregroundStyle(.secondary)
                }
            }

            if !setup.isBundled {
                Label("Drag Secure Agent.app to /Applications and relaunch it to install.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            GroupBox("1. Background Monitor") {
                HStack {
                    Image(systemName: setup.isDaemonRunning ? "checkmark.circle.fill" : "circle.dotted")
                        .foregroundStyle(setup.isDaemonRunning ? .green : .secondary)
                    Text(setup.isDaemonRunning
                         ? "Monitor running — starts and stops with this app"
                         : "Starting monitor…")
                        .font(.callout)
                    Spacer()
                    Button("Recheck") { Task { await setup.refreshState() } }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("2. Full Disk Access") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("File monitoring requires Full Disk Access for the daemon. Add secure-agentd in System Settings, then click Recheck.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Button("Open Privacy Settings") { setup.openFullDiskAccessSettings() }
                        Button("Recheck") { Task { await setup.refreshState() } }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("3. Harness Hooks") {
                stepRow(
                    done: setup.areHooksInstalled,
                    installed: setup.areHooksInstalled,
                    title: setup.areHooksInstalled ? "Hooks installed (Claude, Cursor, opencode)" : "Install Claude / Cursor / opencode hooks",
                    buttonTitle: setup.areHooksInstalled ? "Installed" : "Install Hooks",
                    action: { try setup.installHooks() }
                )
            }

            GroupBox("4. Extras") {
                HStack {
                    Button("Open at Login") { run { try setup.enableLoginItem() } }
                        .disabled(setup.isLoginItemEnabled)
                    Button("Install CLI Tool") { run { try setup.installCLI() } }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            GroupBox("5. Agent Routing (optional)") {
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

            GroupBox("6. Secret Registry (optional)") {
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

            GroupBox("7. Guard Your Secrets") {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Turn on the interactive guard for SSH keys, cloud credentials, and the keychain. When an agent reaches for one, you get a native Allow / Deny prompt. Nothing is blocked until you choose.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Guard My Secrets") { setup.enableGuardClassics() }
                        .disabled(setup.didGuardClassics)
                    if setup.didGuardClassics {
                        Text("Guarding SSH keys, cloud credentials, and keychain — you'll be prompted on first access.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
            }

            if let err = setup.lastError {
                Text(err).foregroundStyle(.red).font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            }
            .padding(24)
          }

          Divider()
          HStack {
              Spacer()
              Button(setup.needsSetup ? "Finish Later" : "Done") { onDone() }
                  .keyboardShortcut(.defaultAction)
          }
          .padding(.horizontal, 24)
          .padding(.vertical, 12)
        }
        .frame(width: 480, height: 600)
        .task { await setup.refreshState() }
    }

    @ViewBuilder
    private func stepRow(done: Bool, installed: Bool, title: String, buttonTitle: String,
                         action: @escaping () throws -> Void) -> some View {
        HStack {
            Image(systemName: done ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(done ? .green : .secondary)
            Text(title).font(.callout)
            Spacer()
            Button(buttonTitle) { run(action) }
                .disabled(installed && done)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
    }

    private func run(_ action: () throws -> Void) {
        do {
            try action()
        } catch {
            setup.report(error)
        }
        Task { await setup.refreshState() }
    }
}
