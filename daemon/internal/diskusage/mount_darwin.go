//go:build darwin

package diskusage

import "golang.org/x/sys/unix"

// mountPoint is the volume's mount path as the kernel reports it.
func mountPoint(st *unix.Statfs_t) string {
	b := make([]byte, 0, len(st.Mntonname))
	for _, c := range st.Mntonname {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
