import XCTest
@testable import SecureAgentMenubar

@MainActor
final class RefreshHealthTests: XCTestCase {
    private final class RefreshFailure: Error {}

    func testSuccessfulRefreshReturnsValueWithoutWarning() async throws {
        let health = RefreshHealth()
        XCTAssertNil(health.warning)
        let value = try await health.refresh(.status) { 42 }
        XCTAssertEqual(value, 42)
        XCTAssertTrue(health.staleSections.isEmpty)
        XCTAssertNil(health.warning)
    }

    func testFailurePreservesOriginalError() async {
        let health = RefreshHealth()
        let failure = RefreshFailure()
        do {
            _ = try await health.refresh(.posture) { throw failure }
            XCTFail("Failed refresh must throw")
        } catch {
            XCTAssertTrue((error as? RefreshFailure) === failure)
        }
        XCTAssertEqual(health.staleSections, [.posture])
    }

    func testRecoveryClearsOnlyTheSectionThatSucceeded() async throws {
        let health = RefreshHealth()
        let failure = RefreshFailure()
        _ = try? await health.refresh(.findings) { throw failure }
        _ = try? await health.refresh(.posture) { throw failure }
        // A healthy unrelated endpoint cannot make failed endpoints fresh.
        _ = try await health.refresh(.status) { true }
        XCTAssertEqual(health.staleSections, [.findings, .posture])
        _ = try await health.refresh(.posture) { true }
        XCTAssertEqual(health.staleSections, [.findings])
        _ = try await health.refresh(.findings) { true }
        XCTAssertTrue(health.staleSections.isEmpty)
        XCTAssertNil(health.warning)
    }

    func testWarningUsesStableOperatorLabelsAndOrder() async {
        let health = RefreshHealth()
        let failure = RefreshFailure()
        _ = try? await health.refresh(.posture) { throw failure }
        _ = try? await health.refresh(.guardDecisions) { throw failure }
        _ = try? await health.refresh(.findings) { throw failure }
        XCTAssertEqual(health.warning, "Could not refresh: Findings, Guard decisions, Posture. Showing last available data; freshness is unknown.")
    }
}
