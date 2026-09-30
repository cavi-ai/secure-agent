import Foundation

enum AppIdentity {
    static let bundleIdentifier = "com.cavi-ai.secure-agent.ui"
    static let legacyBundleIdentifier = "com.cavi-ai.secure-agent"
    static let uiBundleIdentifiers = [bundleIdentifier, legacyBundleIdentifier]
}

/// Preferences belong to Secure Agent, independently of the UI's Launch
/// Services identity. Keep the established suite so an upgrade preserves
/// telemetry opt-outs, onboarding, update channel and digest state.
@MainActor
enum AppPreferences {
    static let shared = UserDefaults(suiteName: AppIdentity.legacyBundleIdentifier)!
}
