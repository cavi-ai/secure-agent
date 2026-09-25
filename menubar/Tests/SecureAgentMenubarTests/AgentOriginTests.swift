import XCTest
@testable import SecureAgentMenubar

/// /status tree roots carry the spawning agent (`origin`); the session card
/// names it after the folder, as the console's session titles do.
final class AgentOriginTests: XCTestCase {
    func testTreeRootDecodesOriginAndTheCardNamesTheAgent() throws {
        let json = """
        {"root": {"pid": 4412, "name": "codex", "cwd": "/", "root_pid": 4412, "session_id": "s1",
                  "repo": "demo-app", "branch": "main", "origin": "quill (openclaw)"}, "children": []}
        """
        let tree = try JSONDecoder().decode(AgentTreeModel.self, from: Data(json.utf8))
        XCTAssertEqual(tree.root.origin, "quill (openclaw)")
        XCTAssertEqual(tree.root.originAgent, "quill")
        XCTAssertEqual(tree.root.cardTitle, "demo-app · quill")
        XCTAssertEqual(tree.root.repoBranch, "demo-app@main")
    }

    func testRootWithoutOriginKeepsTheFolderTitle() throws {
        let json = """
        {"root": {"pid": 5821, "name": "claude", "cwd": "/Users/dev/workspace/api-service"}, "children": []}
        """
        let tree = try JSONDecoder().decode(AgentTreeModel.self, from: Data(json.utf8))
        XCTAssertNil(tree.root.origin)
        XCTAssertEqual(tree.root.originAgent, "")
        XCTAssertEqual(tree.root.cardTitle, "api-service")
    }
}
