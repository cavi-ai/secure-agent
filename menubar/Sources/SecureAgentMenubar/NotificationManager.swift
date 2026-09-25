import Foundation
import UserNotifications

public final class NotificationManager: NSObject, @unchecked Sendable {
    public static let shared = NotificationManager()

    public static let flagCategory = "secure-agent.flag"
    public static let killAction = "secure-agent.kill"
    public static let openAction = "secure-agent.open"

    private var isSupported: Bool { Bundle.main.bundleIdentifier != nil }

    /// Internal (not private) so tests build an instance with their own
    /// clock and reconcile seam.
    override init() { super.init() }

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
            print("[secure-agent-menubar] Alert [\(flag.rule)]: \(flag.evidence.map(\.displayText).joined(separator: ", "))")
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

    public func sendResourceNotification(_ notice: ResourceInterventionNotice) {
        let action = (notice.action ?? notice.state).replacingOccurrences(of: "_", with: " ")
        if !isSupported {
            print("[secure-agent-menubar] Resource intervention [\(notice.sessionName)]: \(action)")
            return
        }
        let content = UNMutableNotificationContent()
        content.title = notice.error == nil ? "Agent resource intervention" : "Resource intervention failed"
        content.subtitle = notice.sessionName.capitalized
        content.body = notice.error == nil ? action.capitalized : "Open the console to review the failure."
        content.interruptionLevel = notice.error == nil ? .active : .timeSensitive
        content.sound = notice.error == nil ? .default : .defaultCritical
        let request = UNNotificationRequest(identifier: "secure-agent.resource.\(notice.sessionKey).\(UUID().uuidString)",
                                            content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                NSLog("[secure-agent] Failed to deliver resource notification: \(error.localizedDescription)")
            }
        }
    }

    /// Clock for the reconcile gate; tests inject their own.
    var clock: () -> Date = { Date() }
    /// The reconcile pass itself; tests replace it with a counter.
    lazy var reconcileRunner: (Set<String>, TimeInterval) -> Void = { [unowned self] ids, maxAge in
        self.reconcileNow(acknowledgedIDs: ids, maxAge: maxAge)
    }
    private var lastReconciledIDs: Set<String>?
    private var lastReconcileAt: Date?
    /// A poll with an unchanged acknowledged set reconciles at most this often.
    static let reconcileInterval: TimeInterval = 60

    /// Notification Center must track live posture, not accumulate grey
    /// history: banners whose flag the operator already acted on (dismissed
    /// in either UI, muted, or retro-acknowledged daemon-side — all converge
    /// to `acknowledged`) are withdrawn, and anything older than maxAge is
    /// pruned. Called on every poll; runs when the acknowledged set changed
    /// since the last run, else at most once a minute.
    public func reconcileDeliveredNotifications(acknowledgedIDs: Set<String>,
                                                maxAge: TimeInterval = 7 * 24 * 3600) {
        let now = clock()
        if acknowledgedIDs == lastReconciledIDs, let last = lastReconcileAt,
           now.timeIntervalSince(last) < Self.reconcileInterval {
            return
        }
        lastReconciledIDs = acknowledgedIDs
        lastReconcileAt = now
        reconcileRunner(acknowledgedIDs, maxAge)
    }

    private func reconcileNow(acknowledgedIDs: Set<String>, maxAge: TimeInterval) {
        // getDeliveredNotifications needs a real app bundle proxy — it throws
        // NSInternalInconsistencyException in the xctest host, where Bundle
        // lookups otherwise succeed (bundleURL ends in usr/bin, not .app).
        // Skip the whole path when we're not inside a real .app bundle.
        guard isSupported, Bundle.main.bundleURL.pathExtension == "app" else { return }
        UNUserNotificationCenter.current().getDeliveredNotifications { notes in
            let pairs = notes.map { (id: $0.request.identifier, date: $0.date) }
            let remove = Self.identifiersToRemove(delivered: pairs, acknowledgedIDs: acknowledgedIDs,
                                                  maxAge: maxAge, now: Date())
            if !remove.isEmpty {
                UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: remove)
            }
        }
    }

    /// Pure decision, unit-testable: which delivered identifiers leave the
    /// Center. A banner leaves when its flag is acknowledged (acted on — the
    /// whole point of dismissing) or when it's simply too old to be posture.
    static func identifiersToRemove(delivered: [(id: String, date: Date)],
                                    acknowledgedIDs: Set<String>,
                                    maxAge: TimeInterval, now: Date) -> [String] {
        delivered.compactMap { item in
            if acknowledgedIDs.contains(item.id) { return item.id }
            if now.timeIntervalSince(item.date) > maxAge { return item.id }
            return nil
        }
    }

    /// A setup step the user has to take in System Settings. One banner per
    /// identifier: a repeat replaces the earlier one.
    public func sendSetupNotification(_ title: String, identifier: String) {
        guard isSupported else {
            print("[secure-agent-menubar] Setup: \(title)")
            return
        }
        let content = UNMutableNotificationContent()
        content.title = title
        content.interruptionLevel = .active
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                NSLog("[secure-agent] Failed to deliver setup notification: \(error.localizedDescription)")
            }
        }
    }

    /// Weekly digest banner: the scheduled proof the app is working. Plain
    /// counts only — no posture detail on a lock screen.
    public func sendWeeklyDigest(_ summary: String) {
        guard isSupported else {
            print("[secure-agent-menubar] Weekly digest: \(summary)")
            return
        }
        let content = UNMutableNotificationContent()
        content.title = "Secure Agent — this week"
        content.body = summary
        content.interruptionLevel = .active
        let request = UNNotificationRequest(
            identifier: "secure-agent.digest.\(UUID().uuidString)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                NSLog("[secure-agent] Failed to deliver digest: \(error.localizedDescription)")
            }
        }
    }

    /// The daemon-served rule title; the rule id when none is served.
    static func title(for flag: FlagModel) -> String {
        if let served = flag.title, !served.isEmpty { return served }
        return flag.rule
    }
}
