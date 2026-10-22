// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// TestReadsHaveNoEmptyValues: no read shows a zero time, which bao prints
// as year 1, or an empty string. The certificate has been issued and has a
// leftover record, which is when unset times and URLs occur.
func TestReadsHaveNoEmptyValues(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	e.waitFor("www", "a schedule", func(m *certMeta) bool { return m.Renewal != nil })
	if err := putJSON(context.Background(), e.storage, inflightKey("www"), &inflightEntry{
		StartTime: time.Now().UTC(), Account: "le", DNS: "bind", NextCleanupTime: time.Now().Add(time.Hour),
		Published: []publishedRecord{{Domain: "www.example.test", Token: "tok", PublishedTime: time.Now().UTC()}},
	}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"certs/www", "certs/www/info", "certs/www/status", "certs/www/versions/1",
		"accounts/le/status", "status",
		"config/accounts/le", "config/dns/bind", "config/network",
	} {
		resp := e.ok(logical.ReadOperation, path, nil)
		findEmpty(t, path, reflect.ValueOf(resp.Data))
	}
}

func findEmpty(t *testing.T, where string, v reflect.Value) {
	t.Helper()
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if tm, ok := v.Interface().(time.Time); ok {
		if tm.IsZero() {
			t.Errorf("%s is a zero time", where)
		}
		return
	}
	switch v.Kind() {
	case reflect.String:
		if v.String() == "" {
			t.Errorf("%s is an empty string", where)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			findEmpty(t, where+"."+k.String(), v.MapIndex(k))
		}
	case reflect.Slice:
		for i := range v.Len() {
			findEmpty(t, where+"[]", v.Index(i))
		}
	}
}
