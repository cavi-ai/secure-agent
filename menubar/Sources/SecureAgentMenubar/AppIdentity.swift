import Foundation

enum AppIdentity {
    /// The app's one identity. Background Task Management records the
    /// file-telemetry helper under it, so only an app with this identifier
    /// can register or unregister that helper.
    static let bundleIdentifier = "com.cavi-ai.secure-agent"

    /// The one install location. Background Task Management binds the
    /// file-telemetry helper to the copy that registers it, so only this copy
    /// registers, re-registers or repairs the helper.
    static let installedAppPath = "/Applications/Secure Agent.app"

    static let wrongLocationMessage = "Secure Agent must run from /Applications to manage file telemetry"

    /// Whether `bundleURL`, symlinks resolved, is the installed copy.
    /// `installedPath` is compared as given, never resolved.
    static func isInstalledCopy(_ bundleURL: URL, installedPath: String = installedAppPath) -> Bool {
        bundleURL.resolvingSymlinksInPath().standardizedFileURL.path == installedPath
    }
}

/// Preferences live in the standard domain, which for the app is its bundle
/// identifier, com.cavi-ai.secure-agent: the established preferences domain,
/// so telemetry opt-outs, onboarding, update channel and digest state persist
/// across upgrades. A suite named after the app's own bundle identifier is nil.
@MainActor
enum AppPreferences {
    static let shared = UserDefaults.standard
}
