import Foundation

enum AppIdentity {
    /// The app's one identity. Background Task Management records the
    /// file-telemetry helper under it, so only an app with this identifier
    /// can register or unregister that helper.
    static let bundleIdentifier = "com.cavi-ai.secure-agent"
}

/// Preferences live in the app's own suite, so telemetry opt-outs,
/// onboarding, update channel and digest state persist across upgrades.
@MainActor
enum AppPreferences {
    static let shared = UserDefaults(suiteName: AppIdentity.bundleIdentifier)!
}
