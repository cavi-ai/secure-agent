import AppKit

if CommandLine.arguments.count >= 2, CommandLine.arguments[1] == "--model-filter" {
    ModelFilterCommand.run(Array(CommandLine.arguments.dropFirst(2)))
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
_ = NSApplicationMain(CommandLine.argc, CommandLine.unsafeArgv)
