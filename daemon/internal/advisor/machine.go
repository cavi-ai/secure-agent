package advisor

import (
	"os"

	"golang.org/x/sys/unix"
)

// Machine is what the advisor's model choice depends on.
type Machine struct {
	Chip          string `json:"chip"`
	RAMBytes      uint64 `json:"ram_bytes"`
	FreeDiskBytes uint64 `json:"free_disk_bytes"`
}

// MachineProfile reads the chip, total memory and the free space on the
// home volume (where model downloads land). Unknown values stay zero.
func MachineProfile() Machine {
	m := Machine{Chip: chipName(), RAMBytes: totalRAM()}
	if home, err := os.UserHomeDir(); err == nil {
		var st unix.Statfs_t
		if unix.Statfs(home, &st) == nil {
			m.FreeDiskBytes = uint64(st.Bavail) * uint64(st.Bsize)
		}
	}
	return m
}
