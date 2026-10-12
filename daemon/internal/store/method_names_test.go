package store

import (
	"reflect"
	"strings"
	"testing"
)

func TestStoreMethodNamesCarryNoResultSuffix(t *testing.T) {
	typ := reflect.TypeOf(&Store{})
	for i := 0; i < typ.NumMethod(); i++ {
		if name := typ.Method(i).Name; strings.HasSuffix(name, "Result") {
			t.Errorf("method %s ends in Result", name)
		}
	}
}
