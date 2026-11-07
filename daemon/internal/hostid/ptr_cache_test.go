package hostid

import (
	"context"
	"strconv"
	"testing"
)

func TestPTRHistoryDoesNotRetainEveryAddress(t *testing.T) {
	calls := 0
	t.Cleanup(SetLookupAddrForTest(func(context.Context, string) ([]string, error) {
		calls++
		return []string{"edge.example.com."}, nil
	}))
	for i := range 4096 {
		ptrOrgName("2001:db8::" + strconv.FormatInt(int64(i), 16))
	}
	before := calls
	ptrOrgName("2001:db8::fff")
	if calls != before {
		t.Fatal("most recent address was not cached")
	}
	ptrOrgName("2001:db8::0")
	if calls != before+1 {
		t.Fatal("old address retained after thousands of newer addresses")
	}
}
