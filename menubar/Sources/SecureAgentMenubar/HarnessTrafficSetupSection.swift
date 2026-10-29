import SwiftUI

/// Each agent exposes hook registration and the routing it actually supports.
@MainActor
struct HarnessTrafficSetupSection: View {
    @ObservedObject var setup: SetupManager
    @Binding var harness: String
    var onSetup: (String) -> Void

    var body: some View {
        Section("Agent") {
            Picker("Configure", selection: $harness) {
                ForEach(SetupManager.knownAgents, id: \.name) { agent in
                    Text(OnboardingView.title(agent.name)).tag(agent.name)
                }
            }
            .accessibilityIdentifier("settings.traffic.harness")
        }
        if harness == "claude" {
            HarnessHookSetupSection(setup: setup, harnesses: [harness], onSetup: onSetup)
        }
        if harness == "claude" { claudeRouting }
        else { directSetup }
    }

    private var claudeRouting: some View {
        Section("Claude Code traffic inspection") {
            Toggle("Route Claude Code through Secure Agent", isOn: Binding(
                get: { setup.claudeRoutingApplied },
                set: { on in Task { await setup.setClaudeRouting(on) } }
            ))
            .disabled(setup.claudeRoutingChanging)
            .accessibilityIdentifier("settings.traffic.claude-routing")
            Text("Close Claude before changing routing. Anthropic API requests are inspected; other connections pass through unopened.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var directSetup: some View {
        Section(OnboardingView.title(harness)) {
            if FirstUseSetupState.supportsHook(harness) {
                Label(setup.firstUseState.installationStatus(for: harness), systemImage: "shield")
            }
            Button(setup.agentSetupRunning == harness ? "Setting Up…" : "Set Up & Open") {
                Task { await setup.setUpAndOpen(harness) }
            }
            .disabled(setup.agentSetupRunning != nil || setup.hookSetupRunning)
            .accessibilityIdentifier("settings.traffic.setup")
            if let status = setup.agentSetupStatus[harness] { Text(status).foregroundStyle(.secondary) }
            Text("Launch here for tunnel routing; payloads are not inspected. Running apps restart.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
