import SwiftUI

/// Hook configuration remains separate from process-monitoring switches.
@MainActor
struct HarnessHookSetupSection: View {
    @ObservedObject var setup: SetupManager
    var harnesses: [String] = FirstUseSetupState.hookHarnesses
    var onSetup: (String) -> Void

    var body: some View {
        Section {
            ForEach(harnesses, id: \.self) { harness in
                HStack(spacing: 12) {
                    AgentIdentity.tile(harness, size: 22)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(OnboardingView.title(harness)).fontWeight(.medium)
                        Text(setup.firstUseState.installationStatus(for: harness))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(setup.hookSetupRunning ? "Setting Up…" : "Set Up") { onSetup(harness) }
                        .disabled(setup.hookSetupRunning || setup.agentSetupRunning != nil)
                        .accessibilityLabel("Set up \(OnboardingView.title(harness)) hooks")
                        .accessibilityIdentifier("settings.hooks.\(harness)")
                }
            }
        } header: {
            Text("Hook setup")
        } footer: {
            Text("Hooks and traffic routing are configured separately.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
