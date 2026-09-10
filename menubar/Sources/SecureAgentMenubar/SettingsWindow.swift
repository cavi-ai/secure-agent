import AppKit
import SwiftUI

/// The Settings window: the single place for deliberate configuration —
/// guard policy, firewall enforcement, the local advisor, routing, and app
/// extras. The popover stays a glance surface; this window owns the knobs.
@MainActor
public final class SettingsWindowController: NSObject, NSWindowDelegate {
    public static let shared = SettingsWindowController()

    private var window: NSWindow?

    public func show(state: AppState) {
        if let window {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let view = SettingsView(state: state)
        let hosting = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: hosting)
        window.title = "Secure Agent Settings"
        window.styleMask = [.titled, .closable, .miniaturizable]
        window.setContentSize(NSSize(width: 560, height: 480))
        window.center()
        window.isReleasedWhenClosed = false
        window.delegate = self
        self.window = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    public func windowWillClose(_ notification: Notification) {
        window = nil
    }
}

@MainActor
struct SettingsView: View {
    @ObservedObject var state: AppState
    @ObservedObject private var setup = SetupManager.shared

    var body: some View {
        TabView {
            generalTab.tabItem { Label("General", systemImage: "gearshape") }
            guardTab.tabItem { Label("Guard", systemImage: "lock.shield") }
            firewallTab.tabItem { Label("Firewall", systemImage: "flame") }
            advisorTab.tabItem { Label("Advisor", systemImage: "brain") }
        }
        .padding(20)
        .frame(width: 560, height: 480)
        .task { await setup.refreshState() }
    }

    // MARK: General

    private var generalTab: some View {
        Form {
            Section("Background") {
                Toggle("Open at Login", isOn: Binding(
                    get: { setup.isLoginItemEnabled },
                    set: { on in if on { run { try setup.enableLoginItem() } } }
                ))
                .disabled(setup.isLoginItemEnabled)
                HStack {
                    Text("Command-line tool")
                    Spacer()
                    Button("Install secure-agent CLI") { run { try setup.installCLI() } }
                }
            }
            Section("Agent routing") {
                Text("Route agents through the inspection proxy (opt-in, shell-scoped).")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Button("Copy Command") { setup.copyAgentRoutingCommand() }
                    Button("Show File") { setup.revealAgentRoutingSnippet() }
                        .disabled(!setup.isAgentRoutingConfigured)
                }
            }
            Section {
                HStack {
                    Button("Setup & Permissions…") { OnboardingWindowController.shared.show() }
                    Spacer()
                    Button("Uninstall…", role: .destructive) { confirmUninstall() }
                }
            }
            if let err = setup.lastError {
                Text(err).foregroundStyle(.red).font(.caption)
            }
        }
        .formStyle(.grouped)
    }

    private func confirmUninstall() {
        let alert = NSAlert()
        alert.messageText = "Uninstall Secure Agent?"
        alert.informativeText = "Stops the daemon, removes harness hooks, the login item, and the CLI symlink. The app and your logs/config stay."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Uninstall")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        run { try setup.uninstallAll() }
        NSApp.terminate(nil)
    }

    private func run(_ action: () throws -> Void) {
        do { try action() } catch { setup.report(error) }
        Task { await setup.refreshState() }
    }

    // MARK: Guard

    private var guardTab: some View {
        Form {
            Section {
                Text("When an agent tool call touches a guarded path, the rule's mode decides: monitor logs, prompt asks you (Allow Once / Always / Deny), deny blocks outright.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Directory guard rules") {
                let current = setup.currentGuardModes()
                if current.corrupt {
                    Label("guard-modes.json is unreadable — the guard is failing closed (deny) until fixed",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.red)
                }
                ForEach(Self.guardRuleLabels, id: \.id) { rule in
                    HStack {
                        Text(rule.label)
                        Spacer()
                        Picker("", selection: Binding(
                            get: { current.modes[rule.id] ?? "monitor" },
                            set: { newMode in
                                do {
                                    try setup.setGuardMode(ruleID: rule.id, mode: newMode)
                                } catch {
                                    setup.report(error)
                                }
                            }
                        )) {
                            Text("Monitor").tag("monitor")
                            Text("Prompt").tag("prompt")
                            Text("Deny").tag("deny")
                        }
                        .pickerStyle(.segmented)
                        .frame(width: 200)
                        .labelsHidden()
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private static let guardRuleLabels: [(id: String, label: String)] = [
        ("ssh-keys", "SSH private keys"),
        ("cloud-creds", "Cloud credentials"),
        ("keychain", "Keychain"),
        ("env-files", ".env files"),
        ("shell-rc", "Shell config"),
        ("harness-config", "Harness config & hooks"),
    ]

    // MARK: Firewall

    private var firewallTab: some View {
        Form {
            Section {
                Text("Monitor reports leaks without blocking; block stops the request. Promote a rule once you trust its precision.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Egress rules") {
                if state.firewallRules.isEmpty {
                    Text("No egress inspected yet — traffic is scanned as your agents run.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                ForEach(state.firewallRules) { rule in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(rule.id).font(.system(.body, design: .monospaced))
                            Text("\(rule.stat.wouldBlock) would-block · \(rule.stat.blocked) blocked · \(rule.stat.legit) legit")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Picker("", selection: Binding(
                            get: { rule.stat.mode ?? "monitor" },
                            set: { state.setFirewallMode(rule: rule.id, mode: $0) }
                        )) {
                            Text("Monitor").tag("monitor")
                            Text("Block").tag("block")
                        }
                        .pickerStyle(.segmented)
                        .frame(width: 160)
                        .labelsHidden()
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: Advisor

    private var advisorTab: some View {
        Form {
            Section {
                Text("A locally served model triages flags and writes incident narratives — on this machine only. The daemon refuses non-loopback endpoints; verdicts never change enforcement.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("Model server") {
                HStack {
                    Image(systemName: setup.advisorServerReachable ? "checkmark.circle.fill" : "circle.dotted")
                        .foregroundStyle(setup.advisorServerReachable ? .green : .secondary)
                    Text(setup.advisorServerReachable
                         ? "Model server detected at 127.0.0.1:8080"
                         : "No model server on 127.0.0.1:8080")
                    Spacer()
                    Button("Recheck") { Task { await setup.refreshState() } }
                }
                if !setup.advisorServerReachable {
                    Text("Start one with: mlx_lm.server --model mlx-community/Qwen3-4B-Instruct-2507-4bit --port 8080")
                        .font(.caption).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            Section("Advisor") {
                Toggle("Enable local advisor", isOn: Binding(
                    get: { setup.advisorEnabled },
                    set: { setup.setAdvisorEnabled($0) }
                ))
                .disabled(!setup.advisorServerReachable && !setup.advisorEnabled)
                if let note = setup.advisorNote {
                    Text(note).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
    }
}
