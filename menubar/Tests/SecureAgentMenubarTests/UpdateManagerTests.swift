import XCTest
@testable import SecureAgentMenubar

final class UpdateManagerTests: XCTestCase {
    func testIsNewer() {
        // Remote final newer than local rc/describe.
        XCTAssertTrue(UpdateManager.isNewer(remoteTag: "v0.9.0", localVersion: "v0.9.0-rc.3"))
        XCTAssertTrue(UpdateManager.isNewer(remoteTag: "v0.9.0", localVersion: "v0.9.0-rc.3-2-gaddc4b4"))
        // Remote rc newer than older base.
        XCTAssertTrue(UpdateManager.isNewer(remoteTag: "v0.10.0-rc.1", localVersion: "v0.9.0-rc.3"))
        // Not newer: same tag, post-tag local, older remote, local final.
        XCTAssertFalse(UpdateManager.isNewer(remoteTag: "v0.9.0-rc.3", localVersion: "v0.9.0-rc.3"))
        XCTAssertFalse(UpdateManager.isNewer(remoteTag: "v0.9.0-rc.3", localVersion: "v0.9.0-rc.3-2-gaddc4b4"))
        XCTAssertFalse(UpdateManager.isNewer(remoteTag: "v0.9.0-rc.2", localVersion: "v0.9.0-rc.3"))
        XCTAssertFalse(UpdateManager.isNewer(remoteTag: "v0.9.0-rc.1", localVersion: "v0.9.0"))
    }

    func testExpectedSHA256() {
        let sums = """
        abc123  SecureAgent-v0.9.0.dmg
        deadbeef  dist/SecureAgent-v0.9.1.dmg
        short  bad-line
        """
        XCTAssertNil(UpdateManager.expectedSHA256(sums, filename: "SecureAgent-v0.9.0.dmg")) // abc123 not 64 chars
        XCTAssertEqual(UpdateManager.expectedSHA256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  dist/SecureAgent-v1.dmg\n",
            filename: "SecureAgent-v1.dmg"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertNil(UpdateManager.expectedSHA256("", filename: "x.dmg"))
    }

    func testDiscoverRepoFindsThisCheckout() {
        // Start from this test file's own path — walking up must reach the repo.
        let here = URL(fileURLWithPath: #filePath)
        let found = UpdateManager.discoverRepo(from: here)
        XCTAssertNotNil(found)
        XCTAssertTrue(FileManager.default.fileExists(atPath: "\(found ?? "")/packaging/update_nightly.sh"))
    }
}
