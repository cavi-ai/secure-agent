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
                hookRow(harness)
            }
        } header: {
            Text("Hook setup")
        } footer: {
            Text("Hooks and traffic routing are configured separately.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func hookRow(_ harness: String) -> some View {
        let standing = setup.firstUseState.hookSetupStatus(for: harness)
        let active = setup.hookSetupHarness == harness
        let title = OnboardingView.title(harness)
        return HStack(spacing: 12) {
            tile(harness, standing: standing, active: active)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).fontWeight(.medium)
                if active {
                    Text(setup.hookSetupPhase?.title ?? "Setting up")
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(Color.brand)
                } else {
                    Text(standing.headline)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(tint(standing))
                    if let guidance = standing.guidance(for: harness) {
                        Text(guidance)
                            .font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Spacer(minLength: 8)
            trailing(harness, title: title, standing: standing, active: active)
        }
        .accessibilityElement(children: .contain)
        .animation(.easeInOut(duration: 0.2), value: active)
    }

    private func tile(_ harness: String, standing: HookSetupStanding, active: Bool) -> some View {
        ZStack(alignment: .bottomTrailing) {
            AgentIdentity.tile(harness, size: 28)
            if active {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(Color.brand)
                    .padding(2)
                    .background(Circle().fill(.background))
                    .symbolEffect(.pulse, options: .repeating)
            } else if standing != .notInstalled {
                Image(systemName: standing.symbol)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(tint(standing))
                    .background(Circle().fill(.background))
            }
        }
        .frame(width: 28, height: 28)
        .accessibilityHidden(true)
    }

    @ViewBuilder
    private func trailing(_ harness: String, title: String, standing: HookSetupStanding, active: Bool) -> some View {
        if active {
            EmptyView()
        } else if standing != .notInstalled {
            Button("Update") { onSetup(harness) }
                .controlSize(.small)
                .disabled(setup.hookSetupRunning || setup.agentSetupRunning != nil)
                .accessibilityLabel("Update \(title) hooks")
                .accessibilityIdentifier("settings.hooks.\(harness)")
        } else {
            Button("Set Up") { onSetup(harness) }
                .buttonStyle(.borderedProminent)
                .tint(Color.brand)
                .controlSize(.small)
                .disabled(setup.hookSetupRunning || setup.agentSetupRunning != nil)
                .accessibilityLabel("Set up \(title) hooks")
                .accessibilityIdentifier("settings.hooks.\(harness)")
        }
    }

    private func tint(_ standing: HookSetupStanding) -> Color {
        switch standing {
        case .notInstalled, .configured: return .secondary
        case .ready: return .ok
        case .needsActivation, .pluginInstalled: return .warn
        }
    }
}
