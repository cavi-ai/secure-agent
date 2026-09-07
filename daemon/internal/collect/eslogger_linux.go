//go:build linux

package collect

// ESLoggerAvailable is false on Linux: eslogger is a macOS Endpoint Security
// binary. File-activity telemetry degrades to the transcript scanner there.
func ESLoggerAvailable() bool { return false }
