import Foundation
import XCTest
@testable import SecureAgentMenubar

final class AppInstanceGuardTests: XCTestCase {
    func testSecondCopyCannotClaimTheMenuBarLease() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("menubar.lock").path

        let first = InstanceLease()
        let second = InstanceLease()
        XCTAssertTrue(first.acquire(at: path))
        XCTAssertFalse(second.acquire(at: path), "Two app copies must not start competing daemons")

        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)

        first.release()
        XCTAssertTrue(second.acquire(at: path), "A replacement must start after the old copy exits")
        second.release()
    }
}
