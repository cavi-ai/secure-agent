import Foundation
import XCTest
@testable import SecureAgentMenubar

final class BundleUpdateInstallerTests: XCTestCase {
    private struct Rejected: Error {}

    private func fixture() throws -> (root: URL, source: URL, installed: URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let source = root.appendingPathComponent("download/Secure Agent.app")
        let installed = root.appendingPathComponent("Applications/Secure Agent.app")
        for (url, value) in [(source, "new"), (installed, "old")] {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            try Data(value.utf8).write(to: url.appendingPathComponent("version"))
        }
        addTeardownBlock { try FileManager.default.removeItem(at: root) }
        return (root, source, installed)
    }

    func testVerificationFailureKeepsInstalledBundle() async throws {
        let f = try fixture()
        do {
            try await BundleUpdateInstaller.install(from: f.source, to: f.installed,
                verify: { staged in
                    XCTAssertEqual(try String(contentsOf: staged.appendingPathComponent("version"), encoding: .utf8), "new")
                    XCTAssertEqual(try String(contentsOf: f.installed.appendingPathComponent("version"), encoding: .utf8), "old")
                    throw Rejected()
                }, prepareRelaunch: { XCTFail("must not relaunch an unverified bundle") })
            XCTFail("verification must fail")
        } catch is Rejected {}
        XCTAssertEqual(try String(contentsOf: f.installed.appendingPathComponent("version"), encoding: .utf8), "old")
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.installed.deletingLastPathComponent().path), ["Secure Agent.app"])
    }

    func testCopyFailureKeepsInstalledBundle() async throws {
        let f = try fixture()
        try FileManager.default.removeItem(at: f.source)
        do {
            try await BundleUpdateInstaller.install(from: f.source, to: f.installed,
                verify: { _ in XCTFail("copy failed") }, prepareRelaunch: { XCTFail("copy failed") })
            XCTFail("missing source must fail")
        } catch {}
        XCTAssertEqual(try String(contentsOf: f.installed.appendingPathComponent("version"), encoding: .utf8), "old")
    }

    func testRelaunchPreparationFailureRestoresInstalledBundle() async throws {
        let f = try fixture()
        do {
            try await BundleUpdateInstaller.install(from: f.source, to: f.installed,
                verify: { _ in }, prepareRelaunch: {
                    XCTAssertEqual(try String(contentsOf: f.installed.appendingPathComponent("version"), encoding: .utf8), "new")
                    throw Rejected()
                })
            XCTFail("relaunch preparation must fail")
        } catch is Rejected {}
        XCTAssertEqual(try String(contentsOf: f.installed.appendingPathComponent("version"), encoding: .utf8), "old")
    }

    func testSuccessfulInstallReplacesWholeBundleAndCleansStaging() async throws {
        let f = try fixture()
        try Data("obsolete".utf8).write(to: f.installed.appendingPathComponent("old-only"))
        try await BundleUpdateInstaller.install(from: f.source, to: f.installed,
            verify: { _ in }, prepareRelaunch: {})
        XCTAssertEqual(try String(contentsOf: f.installed.appendingPathComponent("version"), encoding: .utf8), "new")
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.installed.appendingPathComponent("old-only").path))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.installed.deletingLastPathComponent().path), ["Secure Agent.app"])
    }

    func testRelaunchWaitsForParentExit() async throws {
        let f = try fixture()
        let parent = Process()
        parent.executableURL = URL(fileURLWithPath: "/bin/cat")
        let input = Pipe()
        parent.standardInput = input
        try parent.run()
        defer { if parent.isRunning { parent.terminate() } }
        let marker = f.root.appendingPathComponent("relaunch")
        let helper = try BundleUpdateInstaller.startAfterExit(of: parent.processIdentifier,
            executable: URL(fileURLWithPath: "/usr/bin/touch"), arguments: [marker.path])
        defer { if helper.isRunning { helper.terminate() } }
        // An update may wait on slow shutdown; the helper must survive the
        // previous 30-second expiry instead of leaving the app closed.
        try await Task.sleep(for: .seconds(31))
        XCTAssertTrue(helper.isRunning)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
        try input.fileHandleForWriting.close()
        parent.waitUntilExit()
        for _ in 0..<40 {
            if !helper.isRunning { break }
            try await Task.sleep(for: .milliseconds(50))
        }
        XCTAssertFalse(helper.isRunning)
        if !helper.isRunning { XCTAssertEqual(helper.terminationStatus, 0) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
    }
}
