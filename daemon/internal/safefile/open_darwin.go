package safefile

import "golang.org/x/sys/unix"

// Pin the parent for relative lookups without requiring directory read access.
const parentDirectoryAccess = unix.O_SEARCH
