import XCTest
@testable import SecureAgentMenubar

final class ModelRuntimeInstallTests: XCTestCase {
    @MainActor
    func testPrivateInstallUsesBundledCLIAndReportsFailure() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let cli = root.appendingPathComponent("Contents/Helpers/secure-agent")
        try FileManager.default.createDirectory(at: cli.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data().write(to: cli)
        let defaults = try XCTUnwrap(UserDefaults(suiteName: "ModelRuntimeInstallTests.\(UUID().uuidString)"))
        let setup = SetupManager(esService: FakeESService(), defaults: defaults, configurationHome: root.path, plistPresent: { false }, openPane: { _ in }, appURL: root, deferAutomaticTelemetry: true)
        setup.runProcess = { binary, args in
            XCTAssertEqual(binary, cli.path)
            XCTAssertEqual(args, ["model-runtime", "install"])
            return (1, "", "fixture failure")
        }
        await setup.installModelRuntime()
        XCTAssertFalse(setup.modelRuntimeInstalling)
        XCTAssertTrue(setup.modelRuntimeInstallStatus.contains("failed"))
        setup.runProcess = { _, _ in (0, "", "") }
        await setup.installModelRuntime()
        XCTAssertTrue(setup.modelRuntimeInstallStatus.contains("installed"))
        try FileManager.default.removeItem(at: cli)
        setup.runProcess = { _, _ in XCTFail("Unbundled setup cannot execute a CLI"); return (0, "", "") }
        await setup.installModelRuntime()
        XCTAssertTrue(setup.modelRuntimeInstallStatus.contains("from your checkout"))
    }
}
