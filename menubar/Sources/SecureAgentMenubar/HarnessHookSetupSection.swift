import SwiftUI

/// Hook configuration remains separate from process-monitoring switches.
@MainActor
struct HarnessHookSetupSection: View {
    @ObservedObject var setup: SetupManager
    var onSetup: (String) -> Void

    var body: some View {
        Section {
            ForEach(["codex", "openclaw"], id: \.self) { harness in
                HStack(spacing: 12) {
                    AgentIdentity.tile(harness, size: 22)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(OnboardingView.title(harness)).fontWeight(.medium)
                        Text(setup.firstUseState.installationStatus(for: harness))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Set Up…") { onSetup(harness) }
                        .disabled(setup.hookSetupRunning)
                        .accessibilityLabel("Set up \(OnboardingView.title(harness)) hooks")
                        .accessibilityIdentifier("settings.hooks.\(harness)")
                }
            }
        } header: {
            Text("Hook setup")
        } footer: {
            Text("Register hooks, review activation steps, and inspect session evidence in Setup. Monitoring switches do not install or enable hooks.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
