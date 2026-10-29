// secure-agent-image-text <image>: prints {"readings":[{"view","text"}]}, the
// text macOS Vision reads in the image at full size, at the sizes models
// downscale to, and with contrast raised. The guard hook runs it on an image
// before the agent reads it.
import Foundation
import ImageTextCore

let args = CommandLine.arguments
guard args.count == 2 else {
    FileHandle.standardError.write(Data("usage: secure-agent-image-text <image>\n".utf8))
    exit(64)
}
do {
    let readings = try readImageText(at: URL(fileURLWithPath: args[1]))
    FileHandle.standardOutput.write(try JSONEncoder().encode(["readings": readings]))
} catch {
    FileHandle.standardError.write(Data("secure-agent-image-text: \(error)\n".utf8))
    exit(1)
}
