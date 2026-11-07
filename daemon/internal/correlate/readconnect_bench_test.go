package correlate

import (
	"strconv"
	"testing"
	"time"
)

func BenchmarkFoldBurst(b *testing.B) {
	for _, count := range []int{1000, 8000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			keys := make([]string, count)
			for i := range keys {
				keys[i] = strconv.Itoa(i)
			}
			at := time.Unix(1700000000, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				c := &Correlator{}
				for _, key := range keys {
					c.foldLocked(key, "finding", at, 3)
				}
			}
		})
	}
}
