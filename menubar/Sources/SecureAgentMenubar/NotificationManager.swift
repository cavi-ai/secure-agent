import Foundation
import UserNotifications

public final class NotificationManager: NSObject, @unchecked Sendable {
    public static let shared = NotificationManager()

    public static let flagCategory = "secure-agent.flag"
    public static let killAction = "secure-agent.kill"
    public static let openAction = "secure-agent.open"

    private var isSupported: Bool { Bundle.main.bundleIdentifier != nil }

    override private init() { super.init() }

    /// Whether the user granted notification permission. When denied, security
    /// alerts would vanish silently — the app surfaces this state instead.
    public private(set) var authorizationGranted = false
    /// Set after the first authorization query completes.
    public private(set) var authorizationResolved = false

    public func requestAuthorization() {
        guard isSupported else {
            print("[secure-agent-menubar] Unbundled process context; skipping notification auth.")
            return
        }
        registerCategories()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                print("[secure-agent-menubar] Notification auth error: \(error)")
            }
            self.authorizationGranted = granted
            self.authorizationResolved = true
            if !granted {
                NSLog("[secure-agent] WARNING: notification permission denied — security alerts will not be shown")
            }
        }
    }

    /// Register the actionable category once, so flag notifications carry inline
    /// "Kill agent" and "Open console" buttons.
    public func registerCategories() {
        guard isSupported else { return }
        let kill = UNNotificationAction(identifier: Self.killAction, title: "Kill agent", options: [.destructive])
        let open = UNNotificationAction(identifier: Self.openAction, title: "Open console", options: [.foreground])
        let category = UNNotificationCategory(identifier: Self.flagCategory, actions: [kill, open],
                                              intentIdentifiers: [], options: [])
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    /// Strip anything path-like or host-like from evidence for the lock screen:
    /// notification bodies are visible without unlocking, so "anthropic-key
    /// detected in request body to logs.example.com" would leak posture detail
    /// to a shoulder-surfer. The full evidence is one click away in the console.
    static func redactedBody(for flag: FlagModel) -> String {
        let title = Self.title(for: flag)
        if title != flag.rule { return title }
        return flag.rule.replacingOccurrences(of: "-", with: " ")
    }

    public func sendNotification(for flag: FlagModel) {
        guard isSupported else {
            print("[secure-agent-menubar] Alert [\(flag.rule)]: \(flag.evidence.joined(separator: ", "))")
            return
        }
        let content = UNMutableNotificationContent()
        content.title = Self.title(for: flag)
        content.subtitle = "\(flag.agent.capitalized) · PID \(flag.pid)"
        content.body = Self.redactedBody(for: flag)
        content.categoryIdentifier = Self.flagCategory
        content.userInfo = ["pid": Int(flag.pid), "agent": flag.agent, "rule": flag.rule]
        content.interruptionLevel = flag.severity >= 3 ? .timeSensitive : .active
        content.sound = flag.severity >= 3 ? .defaultCritical : .default

        let request = UNNotificationRequest(identifier: flag.id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                // Not print(): an undelivered severity-3 alert is a security
                // signal, and a bundled GUI app has no stdout anyone reads.
                NSLog("[secure-agent] Failed to deliver notification: \(error.localizedDescription)")
            }
        }
    }

    /// A human, product-voice title per rule (falls back to the rule id).
    static func title(for flag: FlagModel) -> String {
        switch flag.rule {
        case "proxy-secret-leak": return "Secret leaving in agent traffic"
        case "sensitive-read-then-connect": return "Agent read a secret, then connected out"
        case "keychain-access": return "Agent touched the keychain"
        case "keychain-security-cli": return "Agent ran the keychain CLI"
        case "tcc-tamper": return "Agent modified macOS permissions (TCC)"
        case "proxy-prompt-injection": return "Prompt injection in a response"
        default: return flag.rule
        }
    }
}
