import AppKit
import SwiftUI

@MainActor
struct OnboardingView: View {
    @ObservedObject var setup: SetupManager
    @ObservedObject var appState: AppState
    var onOpenConsole: ((ConsoleDestination?) -> Void)?
    var onDone: () -> Void
    var refreshAutomatically = true
    @StateObject private var flow: FirstUseSetupFlow
    @State private var selectionInitialized = false
    @State private var optionsExpanded = false
    @State private var installing = false
    @State private var sampleCopyStatus: String?

    init(setup: SetupManager = .shared, appState: AppState, flow: FirstUseSetupFlow? = nil,
         refreshAutomatically: Bool = true, onOpenConsole: ((ConsoleDestination?) -> Void)? = nil, onDone: @escaping () -> Void) {
        self.setup = setup
        self.appState = appState
        self.onOpenConsole = onOpenConsole
        self.onDone = onDone
        self.refreshAutomatically = refreshAutomatically
        _flow = StateObject(wrappedValue: flow ?? FirstUseSetupFlow())
    }

    private var stage: FirstUseSetupStage { flow.stage }
    private var selectedHarness: String { flow.selectedHarness }

    private var state: FirstUseSetupState { setup.firstUseState }
    private var supported: Bool { FirstUseSetupState.supportsHook(selectedHarness) }
    private var installed: Bool { state.installedHarnesses.contains(selectedHarness) }
    private var harnessTitle: String { Self.title(selectedHarness) }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 12) {
                    AppBrandMark(size: 44)
                    Text("Set up one agent path").font(.title2.weight(.semibold))
                }
                HStack(spacing: 18) {
                    step("Choose", active: stage == .choose)
                    step("Enable", active: stage == .enable)
                    step("Result", active: stage == .result)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(24)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch stage {
                    case .choose: choosePath
                    case .enable: enablePath
                    case .result: result
                    }
                    if let error = setup.lastError {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .font(.callout).foregroundStyle(.red)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading).padding(24)
            }
            Divider()
            footer.padding(.horizontal, 24).padding(.vertical, 14)
        }
        .frame(minWidth: 520, minHeight: 580)
        .background(Color.appSurface)
        .tint(Color.brand)
        .preferredColorScheme(.dark)
        .task {
            guard refreshAutomatically else { return }
            await setup.refreshState()
            if !selectionInitialized {
                flow.selectedHarness = state.suggestedHarness
                selectionInitialized = true
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            guard refreshAutomatically else { return }
            Task { await setup.refreshState() }
        }
    }

    private func step(_ title: String, active: Bool) -> some View {
        Label(title, systemImage: active ? "circle.inset.filled" : "circle")
            .font(.callout.weight(active ? .semibold : .regular))
            .foregroundStyle(active ? .primary : .secondary)
            .accessibilityLabel("\(title)\(active ? ", current step" : "")")
    }

    private var choosePath: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Choose the agent you use. You can add other capabilities after seeing this path's result.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            GroupBox("Agent") {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("Agent to set up", selection: $flow.selectedHarness) {
                        ForEach(FirstUseSetupState.hookHarnesses, id: \.self) { harness in
                            Text(Self.title(harness)).tag(harness)
                        }
                        ForEach(SetupManager.knownAgents.filter { !FirstUseSetupState.supportsHook($0.name) }, id: \.name) { agent in
                            Text("\(Self.title(agent.name)) · observation").tag(agent.name)
                        }
                    }
                    .accessibilityIdentifier("setup.harness")
                    .onChange(of: selectedHarness) { _, _ in selectionInitialized = true }
                    Text(state.activeHarnesses.contains(selectedHarness) ? "Running process detected" :
                         state.configuredHarnesses.contains(selectedHarness) ? "Existing harness configuration found" :
                         "No running process or existing configuration detected for this agent.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
            }
            GroupBox("Available paths") {
                VStack(alignment: .leading, spacing: 12) {
                    capability("Guarding tool requests", detail: supported
                        ? "Install this harness's hooks to use the existing file-access policies and approval prompts."
                        : "This harness has no supported interactive guard hook. Observation remains available.")
                    capability("Session activity", detail: "Recorded tool and system activity can show what was observed. Missing activity remains unknown.")
                    capability("Payload inspection", detail: "Requires separate traffic routing. Hook installation does not establish outbound payload inspection.")
                }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
            }
        }
    }

    private var enablePath: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("\(harnessTitle) hooks").font(.headline)
            Text(selectedHarness == "openclaw"
                 ? "Install the Secure Agent plugin in ~/.openclaw/extensions/secure-agent and enable it through the OpenClaw CLI. This configures the default OpenClaw profile. Existing plugins and settings are retained."
                 : "Install scripts in ~/.\(selectedHarness)/hooks and register them in \(selectedHarness == "claude" ? "~/.claude/settings.json" : "~/.\(selectedHarness)/hooks.json"). Existing user hooks are retained. Only this harness is changed.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Label(installed ? (selectedHarness == "openclaw" ? "Plugin files installed" : "Selected hooks installed and registered") : "Selected hooks not installed",
                  systemImage: installed ? "checkmark.circle" : "circle.dotted")
            Text(FirstUseSetupState.supportsProbe(selectedHarness)
                 ? "The check sends an inert request through the installed hook and verifies the monitor's deny response. It changes no policy and does not launch an agent or establish that a running agent invokes the hook."
                 : FirstUseSetupState.activationGuidance(selectedHarness))
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            monitorStatus
            if !setup.isBundled {
                Text("Use the packaged Secure Agent app to install hooks.")
                    .font(.callout).foregroundStyle(.orange)
            }
            Button(FirstUseSetupState.supportsProbe(selectedHarness) ? "View result without running a check" : "View activation steps") { flow.stage = .result }
                .accessibilityIdentifier("setup.skip-check")
        }
    }

    private var result: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("\(harnessTitle) result").font(.headline)
            if setup.hookSelfTestRunning {
                HStack { ProgressView().controlSize(.small); Text("Checking the installed hook and monitor round trip…") }
            } else {
                let outcome = state.result(for: selectedHarness)
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Label(outcome.title, systemImage: outcome.passed ? "checkmark.circle" : "info.circle")
                            .font(.headline)
                        Text(outcome.detail).font(.callout).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        if let receipt = state.receipt(for: selectedHarness) {
                            Text("Last recorded check: \(receipt.checkedAt)").font(.caption).foregroundStyle(.secondary)
                            Text(receipt.hookPath).font(.caption).foregroundStyle(.secondary)
                                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                }
                if let failure = setup.hookSelfTestFailure, setup.hookSelfTestHarness == selectedHarness {
                    Text(failure).font(.callout).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                }
            }
            monitorStatus
            if FirstUseSetupState.supportsProbe(selectedHarness) && installed {
                Button("Check Selected Hook Again") { runCheck() }
                    .disabled(setup.hookSelfTestRunning || !state.daemonAvailable)
            }
            sessionCoverage
            DisclosureGroup("Optional capabilities", isExpanded: $optionsExpanded) {
                OnboardingOptionsView(setup: setup).padding(.top, 12)
            }
            .accessibilityIdentifier("setup.optional")
            Button("More options in Settings…") { SettingsWindowController.shared.show() }
                .buttonStyle(.link)
        }
    }

    private var monitorStatus: some View {
        HStack {
            Label(state.daemonAvailable ? "Monitor answering" : "Monitor status unavailable",
                  systemImage: state.daemonAvailable ? "checkmark.circle" : "exclamationmark.triangle")
                .font(.callout)
            Spacer()
            Button("Recheck Monitor") { Task { await setup.refreshState() } }
                .disabled(setup.hookSelfTestRunning)
        }
    }

    private var sessionCoverage: some View {
        GroupBox("Your first observed session") {
            VStack(alignment: .leading, spacing: 12) {
                Text("In \(harnessTitle), open a project you recognize and try this task. Keep the session open while checking its observations.")
                    .font(.callout).foregroundStyle(.secondary)
                Text(FirstUseSetupState.sampleTask).font(.callout).textSelection(.enabled)
                Button("Copy sample task") {
                    NSPasteboard.general.clearContents()
                    sampleCopyStatus = NSPasteboard.general.setString(FirstUseSetupState.sampleTask, forType: .string)
                        ? "Sample task copied." : "Could not copy. Select the sample text to copy it manually."
                }
                if let sampleCopyStatus { Text(sampleCopyStatus).font(.caption).foregroundStyle(.secondary) }
                Button("Refresh session observations") { Task { await setup.refreshState() } }
                    .disabled(setup.hookSelfTestRunning)
                let sessions = state.sessions.filter { $0.harness == selectedHarness }
                if !state.daemonAvailable || state.sessionsUnavailable {
                    Label("Current session observations are unavailable. Recheck the monitor, then refresh. Retained results do not establish current coverage.", systemImage: "exclamationmark.triangle")
                        .font(.callout).foregroundStyle(.orange)
                } else if sessions.isEmpty {
                    Text("No session observed for \(harnessTitle) yet. Run the sample task, then refresh. If it is still missing, check the selected harness in Setup and its supported observation path.")
                        .font(.callout).foregroundStyle(.secondary)
                    Button("Review agent setup") { flow.stage = supported ? .enable : .choose }
                }
                if sessions.count > 1 {
                    Text("Choose the workspace and session that match your task.").font(.callout.weight(.medium))
                }
                ForEach(Array(sessions.prefix(3).enumerated()), id: \.offset) { index, session in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(session.workspace ?? "Workspace unknown").font(.callout.weight(.medium)).textSelection(.enabled)
                        if let id = session.sessionID, !id.isEmpty {
                            Text("Session: \(id)").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                        }
                        coveragePath("Guard", session.guardPath)
                        coveragePath("Recorded activity", session.trace)
                        coveragePath("Payload inspection", session.payload)
                        if state.sessionDestination(for: session, harness: selectedHarness) != nil {
                            Button("Open session evidence") { openSession(session) }
                                .keyboardShortcut(KeyEquivalent(Character(String(index + 1))), modifiers: .command)
                                .accessibilityLabel("Open session evidence for \(session.workspace ?? "unknown workspace"), session \(session.sessionID ?? "")")
                                .disabled(appState.dashboardUnavailableReason != nil)
                        } else if session.sessionID?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
                            Text("Session identity is unresolved. Refresh after more activity; a process ID alone cannot select its evidence.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if sessions.count > 1 { Divider() }
                }
                if state.sessionsTruncated || sessions.count > 3 {
                    Text("This setup list shows only part of the observed sessions. Browse Sessions to find another workspace.").font(.caption).foregroundStyle(.secondary)
                    Button("Browse all sessions") { openConsole(nil) }
                        .keyboardShortcut("0", modifiers: .command)
                        .disabled(appState.dashboardUnavailableReason != nil)
                }
                if let reason = appState.dashboardUnavailableReason {
                    Text("Console unavailable: \(reason). Open Settings to review console and traffic options; no routing is enabled by this step.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Open Settings…") { SettingsWindowController.shared.show() }
                }
                if let error = appState.lastError {
                    Text(error).font(.callout).foregroundStyle(.orange)
                }
                Text("A passed hook check confirms its manual round trip. These session observations cover only recorded activity; they do not establish complete protection.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading).padding(4)
        }
    }

    private func openSession(_ session: SessionCoverageModel) {
        guard let destination = state.sessionDestination(for: session, harness: selectedHarness) else { return }
        openConsole(destination)
    }

    private func openConsole(_ destination: ConsoleDestination?) {
        guard appState.dashboardUnavailableReason == nil else { return }
        if let onOpenConsole { onOpenConsole(destination) }
        else { appState.openDashboard(tab: "sessions", destination: destination) }
    }

    private func coveragePath(_ title: String, _ path: CoveragePathModel) -> some View {
        let labels = ["observed": "activity observed", "not-observed": "no activity observed yet",
                      "unsupported": "not supported", "unattributed": "not attributed to this session",
                      "stale": "last-known observation", "off": "off"]
        return VStack(alignment: .leading, spacing: 2) {
            Text("\(title): \(labels[path.state] ?? "unknown")").font(.caption.weight(.medium))
            Text(path.detail).font(.caption).foregroundStyle(.secondary)
            if let seen = path.lastSeen { Text("Last observed: \(seen)").font(.caption).foregroundStyle(.secondary) }
            if path.state == "not-observed" && path.supported {
                Text(title == "Payload inspection" ? "Traffic routing is a separate opt-in. Review Traffic in Settings if needed." : "Run the sample task, then refresh. Check this harness's setup if activity is still missing.")
                    .font(.caption).foregroundStyle(.secondary)
            } else if path.state == "stale" || !["observed", "not-observed", "unsupported", "unattributed", "off"].contains(path.state) {
                Text("Refresh observations before relying on this result.").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func capability(_ title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.callout.weight(.semibold))
            Text(detail).font(.callout).foregroundStyle(.secondary)
        }.fixedSize(horizontal: false, vertical: true)
    }

    private var footer: some View {
        HStack {
            if stage != .choose {
                Button("Change Agent") { flow.stage = .choose }.disabled(setup.hookSelfTestRunning || installing)
            }
            if stage != .result {
                Button("Finish Later", action: onDone).keyboardShortcut(.cancelAction)
            }
            Spacer()
            Button(primaryTitle, action: advance)
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("setup.continue")
                .disabled(setup.hookSelfTestRunning || installing || (stage == .enable &&
                    ((!installed || selectedHarness == "openclaw") ? !setup.isBundled :
                        FirstUseSetupState.supportsProbe(selectedHarness) && !state.daemonAvailable)))
        }
    }

    private var primaryTitle: String {
        switch stage {
        case .choose: return supported ? "Continue" : "View Observation Result"
        case .enable:
            if installing { return "Installing…" }
            if selectedHarness == "openclaw" { return "Register OpenClaw Hooks" }
            if installed { return FirstUseSetupState.supportsProbe(selectedHarness) ? "Run Hook Check" : "Review Activation" }
            return "Install \(harnessTitle) Hooks"
        case .result: return "Close setup"
        }
    }

    private func advance() {
        switch stage {
        case .choose: flow.stage = supported ? .enable : .result
        case .enable:
            if installed && selectedHarness != "openclaw" {
                if FirstUseSetupState.supportsProbe(selectedHarness) { runCheck() }
                else { flow.stage = .result }
            }
            else {
                installing = true
                let harness = selectedHarness
                Task {
                    defer { installing = false }
                    do {
                        try setup.installHooks(for: harness)
                        if harness == "openclaw" { try await setup.registerOpenClawHooks() }
                        await setup.refreshState()
                        if !FirstUseSetupState.supportsProbe(harness) { flow.stage = .result }
                    } catch { setup.report(error); await setup.refreshState() }
                }
            }
        case .result: onDone()
        }
    }

    private func runCheck() {
        flow.stage = .result
        Task { await setup.runHookSelfTest(harness: selectedHarness) }
    }

    static func title(_ harness: String) -> String {
        switch harness {
        case "claude": return "Claude Code"
        case "cursor": return "Cursor"
        case "codex": return "Codex"
        case "openclaw": return "OpenClaw"
        default: return harness
        }
    }
}
