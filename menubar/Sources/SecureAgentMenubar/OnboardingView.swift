import AppKit
import SwiftUI

@MainActor
struct OnboardingView: View {
    @ObservedObject var setup: SetupManager
    var onDone: () -> Void
    var refreshAutomatically = true
    @StateObject private var flow: FirstUseSetupFlow
    @State private var selectionInitialized = false
    @State private var optionsExpanded = false
    @State private var installing = false

    init(setup: SetupManager = .shared, flow: FirstUseSetupFlow? = nil,
         refreshAutomatically: Bool = true, onDone: @escaping () -> Void) {
        self.setup = setup
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
                Text("Set up one agent path").font(.title2).bold()
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
                        Text("Claude Code").tag("claude")
                        Text("Cursor").tag("cursor")
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
            Text("Install scripts in ~/.\(selectedHarness)/hooks and register them in \(selectedHarness == "claude" ? "~/.claude/settings.json" : "~/.cursor/hooks.json"). Existing user hooks are retained. Only this harness is changed.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Label(installed ? "Selected hooks installed and registered" : "Selected hooks not installed",
                  systemImage: installed ? "checkmark.circle" : "circle.dotted")
            Text("The check sends an inert request through the installed hook and verifies the monitor's deny response. It changes no policy and does not launch an agent or establish that a running agent invokes the hook.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            monitorStatus
            if !setup.isBundled {
                Text("Use the packaged Secure Agent app to install hooks.")
                    .font(.callout).foregroundStyle(.orange)
            }
            Button("View result without running a check") { flow.stage = .result }
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
            if supported && installed {
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
        GroupBox("Observed session coverage") {
            VStack(alignment: .leading, spacing: 10) {
                let sessions = state.sessions.filter { $0.harness == selectedHarness }
                if state.sessionsUnavailable {
                    Text("Session coverage is incomplete or unavailable. Refresh before relying on these observations.")
                        .font(.callout).foregroundStyle(.orange)
                }
                if sessions.isEmpty {
                    Text("No session coverage available for \(harnessTitle). Start a session, then recheck. A passed hook check does not establish session coverage.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                ForEach(Array(sessions.prefix(3).enumerated()), id: \.offset) { _, session in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(session.workspace ?? "Workspace unknown").font(.callout.weight(.medium))
                        coveragePath("Guard", session.guardPath)
                        coveragePath("Trace", session.trace)
                        coveragePath("Payload", session.payload)
                    }
                }
                if sessions.count > 3 { Text("Additional sessions are available in the console.").font(.caption) }
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading).padding(4)
        }
    }

    private func coveragePath(_ title: String, _ path: CoveragePathModel) -> some View {
        Text("\(title): \(path.state) — \(path.detail)").font(.caption).foregroundStyle(.secondary)
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
                .disabled(setup.hookSelfTestRunning || installing || (stage == .enable && (installed ? !state.daemonAvailable : !setup.isBundled)))
        }
    }

    private var primaryTitle: String {
        switch stage {
        case .choose: return supported ? "Continue" : "View Observation Result"
        case .enable: return installing ? "Installing…" : installed ? "Run Hook Check" : "Install \(harnessTitle) Hooks"
        case .result: return "Done"
        }
    }

    private func advance() {
        switch stage {
        case .choose: flow.stage = supported ? .enable : .result
        case .enable:
            if installed { runCheck() }
            else {
                installing = true
                do { try setup.installHooks(for: selectedHarness) } catch { setup.report(error) }
                Task { await setup.refreshState(); installing = false }
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
        default: return harness
        }
    }
}
