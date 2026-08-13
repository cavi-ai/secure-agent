import Foundation
import UserNotifications

public final class NotificationManager: NSObject, UNUserNotificationCenterDelegate, Sendable {
    public static let shared = NotificationManager()

    override private init() {
        super.init()
        UNUserNotificationCenter.current().delegate = self
    }

    public func requestAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                print("[secure-agent-menubar] Notification auth error: \(error)")
            }
        }
    }

    public func sendNotification(for flag: FlagModel) {
        let content = UNMutableNotificationContent()
        content.title = "[secure-agent] \(flag.rule)"
        content.subtitle = "Severity \(flag.severity) — \(flag.agent.capitalized) (PID \(flag.pid))"
        content.body = flag.evidence.joined(separator: "\n")
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: flag.id,
            content: content,
            trigger: nil // deliver immediately
        )

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[secure-agent-menubar] Failed to deliver notification: \(error)")
            }
        }
    }

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Show banner and sound even when app is active
        completionHandler([.banner, .sound])
    }
}
