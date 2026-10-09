import XCTest
@testable import SecureAgentMenubar

final class ResourceOutcomeTests: XCTestCase {
 func testResourceOutcomeKeepsApplicationSeparateFromVerification() throws {
  let raw = #"{"host":null,"interventions":[{"id":"r","kind":"pause","status":"partial","verification":"unknown"}]}"#
  let snapshot=try JSONDecoder().decode(ResourceSnapshotModel.self,from:Data(raw.utf8))
  XCTAssertEqual(snapshot.interventions?.first?.summary,"Pause · partially applied · verification unknown")
 }
 func testTerminationVerificationIsLimitedToCapturedFamily() throws {
  let raw = #"{"host":null,"interventions":[{"id":"r","kind":"terminate","status":"applied","verification":"verified","verified_by":"captured-family-absent"}]}"#
  let snapshot=try JSONDecoder().decode(ResourceSnapshotModel.self,from:Data(raw.utf8))
  XCTAssertEqual(snapshot.interventions?.first?.summary,"Terminate · applied · captured family absent")
 }
}
