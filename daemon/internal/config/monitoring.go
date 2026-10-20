package config

// Unspecified preserves existing collector discovery. An explicit opt-out
// pauses collection even when an old spool remains on disk.
func (c Config) FileTelemetryOn() bool {
	return c.FileTelemetryEnabled == nil || *c.FileTelemetryEnabled
}
