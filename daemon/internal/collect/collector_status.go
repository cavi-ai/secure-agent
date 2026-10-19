package collect

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ESCollectorStatusPath is in the root-owned runtime directory. The status
// contains health metadata only; it never grants access or authorizes actions.
const ESCollectorStatusPath = "/var/run/secure-agent-esd-status.json"
const ESCollectorStatusMaxAge = 90 * time.Second

type ESCollectorStatus struct {
	PID            int        `json:"pid"`
	State          string     `json:"state"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastDeliveryAt *time.Time `json:"last_delivery_at,omitempty"`
	HelperMtime    *time.Time `json:"helper_mtime,omitempty"`
}

func (s ESCollectorStatus) Fresh(now time.Time) bool {
	age := now.Sub(s.UpdatedAt)
	return !s.UpdatedAt.IsZero() && age >= -5*time.Second && age <= ESCollectorStatusMaxAge
}

func readESCollectorStatus(path string, pid int, now time.Time) *ESCollectorStatus {
	if pid <= 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil
	}
	var status ESCollectorStatus
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &status) != nil || status.PID != pid || !status.Fresh(now) {
		return nil
	}
	switch status.State {
	case "starting", "collecting", "permission_denied", "restarting", "failed", "stopped":
	default:
		return nil
	}
	if status.LastDeliveryAt != nil && status.LastDeliveryAt.After(status.UpdatedAt) {
		return nil
	}
	return &status
}
