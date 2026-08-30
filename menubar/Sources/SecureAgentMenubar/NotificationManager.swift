import Foundation
import UserNotifications

public final class NotificationManager: NSObject, Sendable {
    public static let shared = NotificationManager()

    public static let flagCategory = "secure-agent.flag"
    public static let killAction = "secure-agent.kill"
    public static let openAction = "secure-agent.open"

    private var isSupported: Bool { Bundle.main.bundleIdentifier != nil }

    override private init() { super.init() }

    public func requestAuthorization() {
        guard isSupported else {
            print("[secure-agent-menubar] Unbundled process context; skipping notification auth.")
            return
        }
        registerCategories()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, error in
            if let error = error {
                print("[secure-agent-menubar] Notification auth error: \(error)")
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

    public func sendNotification(for flag: FlagModel) {
        guard isSupported else {
            print("[secure-agent-menubar] Alert [\(flag.rule)]: \(flag.evidence.joined(separator: ", "))")
            return
        }
        let content = UNMutableNotificationContent()
        content.title = Self.title(for: flag)
        content.subtitle = "\(flag.agent.capitalized) · PID \(flag.pid)"
        content.body = flag.evidence.first ?? flag.rule
        content.categoryIdentifier = Self.flagCategory
        content.userInfo = ["pid": Int(flag.pid), "agent": flag.agent, "rule": flag.rule]
        content.interruptionLevel = flag.severity >= 3 ? .timeSensitive : .active
        content.sound = flag.severity >= 3 ? .defaultCritical : .default

        let request = UNNotificationRequest(identifier: flag.id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[secure-agent-menubar] Failed to deliver notification: \(error)")
            }
        }
    }

    /// A human, product-voice title per rule (falls back to the rule id).
    static func title(for flag: FlagModel) -> String {
        switch flag.rule {
        case "proxy-secret-leak": return "Secret leaving in agent traffic"
        case "sensitive-read-then-connect": return "Agent read a secret, then connected out"
        case "keychain-access": return "Agent touched the keychain"
        case "proxy-prompt-injection": return "Prompt injection in a response"
        default: return flag.rule
        }
    }
}
