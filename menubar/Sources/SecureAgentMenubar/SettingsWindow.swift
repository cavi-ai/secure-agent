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
            updatesTab.tabItem { Label("Updates", systemImage: "arrow.triangle.2.circlepath") }
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

    @State private var advisorMode: SetupManager.AdvisorMode = .managed
    @State private var selectedManagedModel = ""
    @State private var selectedServerID = ""
    @State private var selectedModel = ""

    private var advisorTab: some View {
        let discovery = setup.advisorDiscovery
        let selectedServer = discovery.servers.first { $0.id == selectedServerID } ?? discovery.servers.first
        return Form {
            Section {
                Text("A locally served model triages flags and writes incident narratives — on this machine only. Verdicts never change enforcement.")
                    .font(.caption).foregroundStyle(.secondary)
                Picker("Model source", selection: $advisorMode) {
                    Text("Managed local model").tag(SetupManager.AdvisorMode.managed)
                    Text("Use my existing server").tag(SetupManager.AdvisorMode.existing)
                }
                .pickerStyle(.radioGroup)
            }

            if advisorMode == .managed {
                Section("Managed model") {
                    if discovery.managedModels.isEmpty {
                        Text("Daemon discovery unavailable — restart the app to refresh.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Picker("Model", selection: $selectedManagedModel) {
                            ForEach(discovery.managedModels, id: \.self) { Text($0).tag($0) }
                        }
                        Text("The daemon downloads, starts, and supervises the server itself. First start downloads ~2.3 GB; verdicts begin when ready.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            } else {
                Section("Existing server") {
                    if discovery.servers.isEmpty {
                        Text("No OpenAI-compatible servers found on this machine (probed Ollama, MLX, LM Studio ports). Start one, then Recheck.")
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        Picker("Server", selection: $selectedServerID) {
                            ForEach(discovery.servers) { srv in
                                Text("\(srv.kind == "ollama" ? "Ollama" : "OpenAI-compatible") · \(srv.endpoint.replacingOccurrences(of: "http://", with: "")) · \(srv.models.count) model\(srv.models.count == 1 ? "" : "s")")
                                    .tag(srv.id)
                            }
                        }
                        if let srv = selectedServer {
                            Picker("Model", selection: $selectedModel) {
                                ForEach(srv.models, id: \.self) { Text($0).tag($0) }
                            }
                        }
                    }
                }
            }

            Section("Advisor") {
                let canEnable = advisorMode == .managed
                    ? !discovery.managedModels.isEmpty
                    : selectedServer != nil && !selectedModel.isEmpty
                Button(setup.advisorEnabled ? "Apply configuration" : "Enable advisor") {
                    switch advisorMode {
                    case .managed:
                        setup.setAdvisorConfig(mode: .managed, endpoint: nil,
                                               model: selectedManagedModel.isEmpty ? (discovery.managedModels.first ?? "") : selectedManagedModel)
                    case .existing:
                        if let srv = selectedServer {
                            setup.setAdvisorConfig(mode: .existing, endpoint: srv.endpoint, model: selectedModel)
                        }
                    }
                }
                .disabled(!canEnable)
                if setup.advisorEnabled {
                    Button("Disable advisor") { setup.setAdvisorEnabled(false) }
                }
                if let note = setup.advisorNote {
                    Text(note).font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    Button("Recheck servers") { Task { await setup.refreshState() } }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear {
            if selectedManagedModel.isEmpty { selectedManagedModel = discovery.managedModels.first ?? "" }
            if selectedServerID.isEmpty { selectedServerID = discovery.servers.first?.id ?? "" }
            if selectedModel.isEmpty { selectedModel = selectedServer?.models.first ?? "" }
        }
        .onChange(of: selectedServerID) { _, _ in
            selectedModel = selectedServer?.models.first ?? ""
        }
        .onChange(of: discovery.servers.count) { _, _ in
            if selectedServerID.isEmpty { selectedServerID = discovery.servers.first?.id ?? "" }
            if selectedManagedModel.isEmpty { selectedManagedModel = discovery.managedModels.first ?? "" }
        }
    }

    // MARK: Updates

    @ObservedObject private var updates = UpdateManager.shared

    private var updatesTab: some View {
        Form {
            Section("This build") {
                HStack {
                    Text("Version")
                    Spacer()
                    Text(state.status?.version ?? "dev").font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Picker("Channel", selection: $updates.channel) {
                    ForEach(UpdateManager.Channel.allCases, id: \.self) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                if updates.channel == .nightly {
                    Text("Nightly builds from origin/main of a local git checkout (packaging/update_nightly.sh). Stable installs from the verified release DMG.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Section {
                HStack {
                    Button("Check now") {
                        Task { await updates.checkNow(currentVersion: state.status?.version ?? "dev") }
                    }
                    .disabled(updates.state == .checking || updates.state == .downloading || updates.state == .installing || updates.state == .nightlyRunning)
                    if let v = updates.availableVersion {
                        Button("Install \(v)") {
                            Task { await updates.applyUpdate(currentVersion: state.status?.version ?? "dev") }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
                statusLine(updates.state)
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder
    private func statusLine(_ s: UpdateManager.State) -> some View {
        switch s {
        case .idle:
            EmptyView()
        case .checking:
            Label("Checking…", systemImage: "arrow.triangle.2.circlepath").font(.caption).foregroundStyle(.secondary)
        case .upToDate(let msg):
            Label(msg, systemImage: "checkmark.circle").font(.caption).foregroundStyle(.green)
        case .available(let v):
            Label("Update available: \(v)", systemImage: "arrow.down.circle").font(.caption).foregroundStyle(.orange)
        case .downloading:
            Label("Downloading & verifying…", systemImage: "arrow.down.doc").font(.caption).foregroundStyle(.secondary)
        case .installing:
            Label("Installing…", systemImage: "shippingbox").font(.caption).foregroundStyle(.secondary)
        case .nightlyRunning:
            Label("Building from origin/main…", systemImage: "hammer").font(.caption).foregroundStyle(.secondary)
        case .error(let msg):
            Label(msg, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
