import AppKit
import SwiftUI

/// The Settings window: the single place for deliberate configuration —
/// guard policy, firewall enforcement, the local advisor, routing, and app
/// extras. The popover stays a glance surface; this window owns the knobs.
@MainActor
public final class SettingsWindowController: NSObject, NSWindowDelegate {
    public static let shared = SettingsWindowController()

    private var window: NSWindow?

    /// The shared AppState, set once by the AppDelegate at launch so any
    /// surface (menu, wizard, popover) can open Settings without threading
    /// the state through.
    public var appState: AppState?

    public func show() {
        guard let appState else { return }
        show(state: appState)
    }

    public func show(state: AppState) {
        appState = state
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
            protectionTab.tabItem { Label("Protection", systemImage: "shield.lefthalf.filled") }
            providersTab.tabItem { Label("Providers", systemImage: "app.connected") }
            visibilityTab.tabItem { Label("Telemetry", systemImage: "waveform.path.ecg") }
            policyTab.tabItem { Label("Decisions", systemImage: "checklist") }
            generalTab.tabItem { Label("App", systemImage: "gearshape") }
            advisorTab.tabItem { Label("Advisor", systemImage: "brain") }
            updatesTab.tabItem { Label("Updates", systemImage: "arrow.triangle.2.circlepath") }
        }
        .padding(20)
        .frame(width: 560, height: 480)
        .task {
            await setup.refreshState()
            loadPathAllows()
        }
    }

    // MARK: General

    // MARK: Protection — what actively stops agents

    /// Guard policy + firewall enforcement: the enforcement surface.
    private var protectionTab: some View {
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
            firewallSection
        }
        .formStyle(.grouped)
    }

    // MARK: Telemetry — what watches agents

    /// ES collector install + advisor (the observation layer).
    private var visibilityTab: some View {
        Form {
            Section("File telemetry (Endpoint Security)") {
                ESFileTelemetryCard(setup: setup)
            }
            Section("Transcript & network coverage") {
                HStack {
                    Image(systemName: supervisorCollectorOK ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(supervisorCollectorOK ? Color.ok : Color.warn)
                    Text(supervisorCollectorOK
                         ? "All collectors running"
                         : "A collector is degraded — see the menu bar banner for details")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
    }

    @ObservedObject private var supervisorForTab = DaemonSupervisor.shared
    private var supervisorCollectorOK: Bool {
        !(state.status?.collectors ?? []).contains { $0.abandoned }
    }

    // MARK: Decisions — everything the operator has granted/rejected

    /// Per-path allows + muted flag classes: the reviewable ledger of
    /// dispositions, in one place, each revocable.
    private var policyTab: some View {
        Form {
            Section("Allowed paths (per-path guard exceptions)") {
                Text("Exact files an agent may access without prompting — narrower than a rule allow. Revoking restores prompting for that file.")
                    .font(.caption).foregroundStyle(.secondary)
                if pathAllows.isEmpty {
                    Text("None yet — use “Always allow this file” on an incident to create one.")
                        .font(.caption).foregroundStyle(.tertiary)
                }
                ForEach(pathAllows) { g in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text((g.path as NSString).lastPathComponent)
                                .font(.system(.body, design: .monospaced))
                                .lineLimit(1)
                                .help(g.path)
                            Text("\(g.agent) · \(g.ruleID)")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Revoke", role: .destructive) {
                            revokeGuardPathAllow(agent: g.agent, ruleID: g.ruleID, path: g.path)
                        }
                        .controlSize(.small)
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: Providers — which harnesses are monitored

    /// Per-provider monitoring toggle, backed by disabled_agents in
    /// config.yaml. Off = the daemon ignores that harness's processes
    /// entirely (no tree rows, no flags, no kill buttons).
    private var providersTab: some View {
        Form {
            Section("Monitored harnesses") {
                Text("Disable a harness to stop monitoring its processes. Takes effect on the daemon's next config reload.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(SetupManager.knownAgents, id: \.name) { agent in
                    HStack(spacing: 10) {
                        AgentIdentity.tile(agent.name, size: 22)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(agent.name).font(.system(.body, weight: .medium))
                            Text(agent.matches.joined(separator: " · "))
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.tertiary)
                                .lineLimit(1)
                        }
                        Spacer()
                        Toggle("", isOn: Binding(
                            get: { !setup.disabledAgents.contains(agent.name) },
                            set: { on in setup.setAgentDisabled(agent.name, disabled: !on) }
                        ))
                        .labelsHidden()
                    }
                }
            }
        }
        .formStyle(.grouped)
    }

    private var generalTab: some View {
        Form {
            Section("Background") {
                Toggle("Open at Login", isOn: Binding(
                    get: { setup.isLoginItemEnabled },
                    set: { on in run { if on { try setup.enableLoginItem() } else { try setup.disableLoginItem() } } }
                ))
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
        // Shared confirmation lives in SetupManager; terminate mirrors the
        // right-click menu path (uninstalling without quitting leaves a
        // half-removed monitor running).
        if setup.confirmUninstall() {
            NSApp.terminate(nil)
        }
    }

    private func runAsync(_ action: @escaping () throws -> Void) async {
        do { try action() } catch { setup.report(error) }
        await setup.refreshState()
    }

    private func run(_ action: () throws -> Void) {
        do { try action() } catch { setup.report(error) }
        Task { await setup.refreshState() }
    }

    // MARK: Guard

    @State private var pathAllows: [GuardPathAllowModel] = []

    private func loadPathAllows() {
        Task {
            let rows = (try? await state.uiClient.fetchGuardPathAllows()) ?? []
            await MainActor.run { pathAllows = rows }
        }
    }

    private func revokeGuardPathAllow(agent: String, ruleID: String, path: String) {
        Task {
            do {
                try await state.uiClient.deleteGuardPathAllow(agent: agent, ruleID: ruleID, path: path)
            } catch {
                setup.report(error)
            }
            loadPathAllows()
            state.refresh()
        }
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

    /// Reusable: also embedded in the Protection tab (enforcement lives together).
    private var firewallSection: some View {
        Section("Egress firewall") {
            Text("Monitor reports leaks without blocking; block stops the request. Promote a rule once you trust its precision.")
                .font(.caption).foregroundStyle(.secondary)
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
            // Restore the persisted advisor config FIRST — the tab must not
            // reset to "managed local model" every time Settings opens when
            // the user configured an existing server last time.
            if let m = setup.advisorPersisted.mode {
                advisorMode = m == "managed" ? .managed : .existing
            }
            if let model = setup.advisorPersisted.model, !model.isEmpty {
                if setup.advisorPersisted.mode == "managed" {
                    selectedManagedModel = model
                } else {
                    selectedModel = model
                }
            }
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


/// The guided file-telemetry card: three states, zero guesswork.
///   A. helper missing          → "Enable File Telemetry" (one admin prompt)
///   B. helper running, TCC out → "Open Permissions" + inline instruction
///                                 ("turn ON eslogger"), polling live
///   C. spool flowing           → green, done. Remove stays available.
/// The user never hunts for a pane: the button deep-links to the exact
/// Settings section, and the card self-updates the moment the switch flips.
struct ESFileTelemetryCard: View {
    @ObservedObject var setup: SetupManager
    @State private var polling = false

    private var stage: ESStage {
        if setup.isESCollectorInstalled { return .active }
        if setup.esCollectorDaemonInstalled { return .needsGrant }
        return .notInstalled
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                stageBadge
                VStack(alignment: .leading, spacing: 2) {
                    Text(stage.title).font(.system(.body, weight: .medium))
                    Text(stage.detail)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                controls
            }
            if stage == .needsGrant {
                Label("In the pane that just opened: find **eslogger** in the list and turn its switch ON. This card turns green automatically — nothing else to do.",
                      systemImage: "cursorarrow.click.2")
                    .font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .task { await pollWhileNeeded() }
    }

    private var stageBadge: some View {
        Image(systemName: stage.icon)
            .font(.system(size: 14, weight: .semibold))
            .foregroundStyle(stage.tint)
            .frame(width: 30, height: 30)
            .background(stage.tint.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 7))
    }

    @ViewBuilder
    private var controls: some View {
        switch stage {
        case .notInstalled:
            Button("Enable File Telemetry") {
                Task {
                    do { try await setup.installESCollectorAsync() }
                    catch { /* reported via lastError */ }
                    await pollWhileNeeded()
                }
            }
            .buttonStyle(.borderedProminent).tint(.brand).controlSize(.small)
        case .needsGrant:
            Button("Open Permissions") { setup.openESPermissions() }
                .buttonStyle(.borderedProminent).tint(.brand).controlSize(.small)
        case .active:
            Button("Remove", role: .destructive) {
                Task {
                    setup.uninstallESCollector()
                    await setup.refreshState()
                }
            }
            .controlSize(.small)
        }
    }

    /// Poll the spool while waiting for the grant: the card flips to green
    /// within a second of the switch flipping — no manual refresh.
    private func pollWhileNeeded() async {
        guard stage == .needsGrant else { return }
        while !Task.isCancelled, setup.esCollectorDaemonInstalled, !setup.isESCollectorInstalled {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await setup.refreshState()
        }
    }
}

enum ESStage {
    case notInstalled, needsGrant, active

    var title: String {
        switch self {
        case .notInstalled: return "File telemetry is off"
        case .needsGrant: return "One switch left: allow eslogger"
        case .active: return "File telemetry active"
        }
    }

    var detail: String {
        switch self {
        case .notInstalled:
            return "macOS requires file telemetry (eslogger) to run as root. One admin prompt installs a minimal helper that runs eslogger and nothing else."
        case .needsGrant:
            return "The helper is installed and retrying every 10s. It's waiting on one macOS permission."
        case .active:
            return "The privileged collector is running and the daemon is reading its stream."
        }
    }

    var icon: String {
        switch self {
        case .notInstalled: return "waveform.path.ecg"
        case .needsGrant: return "lock.open"
        case .active: return "checkmark.seal.fill"
        }
    }

    var tint: Color {
        switch self {
        case .notInstalled: return .secondary
        case .needsGrant: return .orange
        case .active: return .ok
        }
    }
}