import Foundation

enum AppIdentity {
    /// The app's one identity. Background Task Management records the
    /// file-telemetry helper under it, so only an app with this identifier
    /// can register or unregister that helper.
    static let bundleIdentifier = "com.cavi-ai.secure-agent"
}

/// Preferences live in the standard domain, which for the app is its bundle
/// identifier, com.cavi-ai.secure-agent: the established preferences domain,
/// so telemetry opt-outs, onboarding, update channel and digest state persist
/// across upgrades. A suite named after the app's own bundle identifier is nil.
@MainActor
enum AppPreferences {
    static let shared = UserDefaults.standard
}
