import XCTest
@testable import SecureAgentMenubar

/// Regression: Notification Center used to pile up greyed-out banners for
/// alerts the operator had already dealt with — nothing ever withdrew a
/// delivered notification. The poll-time reconciliation must remove banners
/// for acknowledged flags and prune stale ones, while leaving fresh,
/// unacted banners (and the weekly digest) alone.
final class NotificationReconcileTests: XCTestCase {
    private let day: TimeInterval = 24 * 3600
    private let week: TimeInterval = 7 * 24 * 3600

    func testAcknowledgedAndStaleBannersLeaveFreshUnactedStay() {
        let now = Date()
        let delivered: [(id: String, date: Date)] = [
            (id: "flag-acked", date: now.addingTimeInterval(-3600)),       // acted on an hour ago
            (id: "flag-fresh", date: now.addingTimeInterval(-3600)),       // still unacted — KEEP
            (id: "flag-ancient", date: now.addingTimeInterval(-30 * day)), // unacted but 30d old — prune
        ]
        let remove = NotificationManager.identifiersToRemove(
            delivered: delivered, acknowledgedIDs: ["flag-acked"], maxAge: week, now: now)
        XCTAssertEqual(Set(remove), ["flag-acked", "flag-ancient"])
    }

    func testDigestBannersExpireByAgeOnly() {
        let now = Date()
        let delivered: [(id: String, date: Date)] = [
            (id: "secure-agent.digest.old", date: now.addingTimeInterval(-10 * day)),
            (id: "secure-agent.digest.new", date: now.addingTimeInterval(-day)),
        ]
        // Digests have no flag id, so acknowledgement can never match them;
        // age is their only expiry.
        let remove = NotificationManager.identifiersToRemove(
            delivered: delivered, acknowledgedIDs: [], maxAge: week, now: now)
        XCTAssertEqual(remove, ["secure-agent.digest.old"])
    }

    func testNothingToRemoveReturnsEmpty() {
        let now = Date()
        let delivered: [(id: String, date: Date)] = [
            (id: "flag-fresh", date: now.addingTimeInterval(-60)),
        ]
        let remove = NotificationManager.identifiersToRemove(
            delivered: delivered, acknowledgedIDs: [], maxAge: week, now: now)
        XCTAssertTrue(remove.isEmpty)
    }

    /// The poll runs once a second; reconciling must not. Same set within a
    /// minute: once. Changed set: again. Same set a minute later: again.
    func testSameSetWithinAMinuteReconcilesOnce() {
        let manager = NotificationManager()
        var now = Date(timeIntervalSince1970: 1_790_000_000)
        var runs = 0
        manager.clock = { now }
        manager.reconcileRunner = { _, _ in runs += 1 }

        manager.reconcileDeliveredNotifications(acknowledgedIDs: ["flag-a"])
        now += 1
        manager.reconcileDeliveredNotifications(acknowledgedIDs: ["flag-a"])
        XCTAssertEqual(runs, 1, "same set one second later")

        now += 1
        manager.reconcileDeliveredNotifications(acknowledgedIDs: ["flag-a", "flag-b"])
        XCTAssertEqual(runs, 2, "a newly acknowledged flag reconciles at once")

        now += 59
        manager.reconcileDeliveredNotifications(acknowledgedIDs: ["flag-a", "flag-b"])
        XCTAssertEqual(runs, 2, "same set 59 s later")

        now += 1
        manager.reconcileDeliveredNotifications(acknowledgedIDs: ["flag-a", "flag-b"])
        XCTAssertEqual(runs, 3, "same set a minute after the last run")
    }
}
