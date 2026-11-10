import Darwin
import Foundation
import XCTest

@testable import ModelFilterCore

final class KernelIdentityTests: XCTestCase {
  func testCurrentIdentityComesFromKernelAuditToken() throws {
    let current = try KernelIdentity.current()
    XCTAssertEqual(current.pid, getpid())
    XCTAssertEqual(current.uid, getuid())
    XCTAssertGreaterThan(current.pidVersion, 0)
    XCTAssertThrowsError(try ProcessIdentity(auditToken: Data(repeating: 0, count: 31)))
    XCTAssertThrowsError(try ProcessIdentity(auditToken: Data(repeating: 0, count: 32)))
  }
}
