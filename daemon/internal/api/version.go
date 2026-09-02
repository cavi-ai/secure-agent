package api

// Version is the daemon/build version, overridable at link time:
//
//	go build -ldflags "-X github.com/cavi-ai/secure-agent/daemon/internal/api.Version=v1.2.3"
//
// "dev" marks builds that never went through the release pipeline; fleet
// consumers can treat it as "unknown, do not trust".
var Version = "dev"

// NodeID is the stable per-install identity reported to fleet consumers. It is
// generated once on first boot and persisted next to the firewall salt.
var NodeID string
