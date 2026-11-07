package testvalue

import (
	"testing"
)

func TestDatabaseSignalsDescribeCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		strong      bool
	}{
		{"dummy credentials", "postgres" + "://test:test@localhost/unit", true},
		{"test database name with real-looking password", "postgres" + "://service:R7qL4vZ9mK2pT5wX@db.internal/unit_test", false},
		{"serialized fixture field after URI", "postgres" + `://service:R7qL4vZ9mK2pT5wX@db.internal/app","note":"fixture"}`, false},
		{"placeholder password", "postgres" + "://service:fixture_password@db.internal/unit", true},
		{"encoded dummy in a query", "postgres" + "://service:R7qL4vZ9mK2pT5wX@db.internal/app?application_name=dGVzdA", false},
		{"mixed compact span", "postgres" + `://test:fixture_password@localhost/unit","postgres` + `://service:R7qL4vZ9mK2pT5wX@db.internal/app`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reasons := Signals(tc.value, 0, len(tc.value)); Strong(reasons) != tc.strong {
				t.Fatalf("strong=%v, want %v; reasons=%v", Strong(reasons), tc.strong, reasons)
			}
		})
	}
}
