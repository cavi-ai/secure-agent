package fleet

import (
	"os"
	"path/filepath"
	"sync"
)

const deliveryLogMaxBytes = 5 << 20

// Sinks, including replacements during reload, share a delivery-log path.
// Serialize rotation and append together without retaining a path registry.
var deliveryLogMu sync.Mutex

// appendDeliveryLog keeps one bounded active generation and one backup. Logs
// are diagnostic history: an oversized legacy generation or record is dropped.
// Delivery never depends on a successful log write.
func appendDeliveryLog(path string, line []byte) {
	if path == "" || len(line) > deliveryLogMaxBytes {
		return
	}
	deliveryLogMu.Lock()
	defer deliveryLogMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return
	}
	info, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	if err == nil {
		if !info.Mode().IsRegular() {
			return
		}
		if info.Size() > deliveryLogMaxBytes {
			if err := os.Remove(path); err != nil {
				return
			}
		} else if info.Size()+int64(len(line)) > deliveryLogMaxBytes {
			if err := os.Rename(path, path+".1"); err != nil {
				return
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}
