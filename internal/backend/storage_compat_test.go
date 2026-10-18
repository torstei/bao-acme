// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/testcerts"
)

// testdata/storage-v1 holds entries exactly as the first released storage
// format (design §5.6) wrote them, one file per storage key. It is frozen:
// never regenerate it. A format change adds a new directory beside it.
const storageV1 = "testdata/storage-v1"

func loadFixture(t *testing.T, h *harness, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		value, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		key, _ := filepath.Rel(dir, path)
		return h.storage.Put(context.Background(), &logical.StorageEntry{Key: filepath.ToSlash(key), Value: value})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readFixture(t *testing.T, key string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(storageV1, key))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReadsStorageV1(t *testing.T) {
	h := newHarness(t)
	loadFixture(t, h, storageV1)
	stored := readFixture(t, "certs/example.com/versions/2")

	read := h.ok(logical.ReadOperation, "certs/example.com", nil)
	if read.Data["fullchain"] != stored["certificate"].(string)+stored["chain"].(string) {
		t.Error("fullchain is not certificate followed by chain")
	}
	if read.Data["privkey"] != stored["privkey"] || read.Data["version"] != 2 {
		t.Errorf("read = %v", read.Data)
	}

	info := h.ok(logical.ReadOperation, "certs/example.com/info", nil)
	desc := stored["description"].(map[string]any)
	if info.Data["sha256"] != desc["sha256"] || info.Data["max_versions"] != 3 {
		t.Errorf("info = %v", info.Data)
	}
	if v1 := info.Data["versions"].(map[string]any)["1"].(map[string]any); v1["destroyed"] != true {
		t.Errorf("version 1 = %v", v1)
	}
	h.fails(logical.ReadOperation, "certs/example.com/versions/1", nil, "destroyed")

	if got := h.ok(logical.ListOperation, "certs/", map[string]any{"covers": "www.example.com"}).Data["keys"]; len(got.([]string)) != 1 {
		t.Errorf("covers = %v", got)
	}
}

func TestWritesStorageV1Fields(t *testing.T) {
	h := newHarness(t)
	h.imp("example.com", testcerts.New(t, testcerts.Options{}))

	for _, key := range []string{"certs/example.com/meta", "certs/example.com/versions/1"} {
		fixtureKey := key
		if strings.HasSuffix(key, "/versions/1") {
			fixtureKey = "certs/example.com/versions/2"
		}
		want := readFixture(t, fixtureKey)

		entry, err := h.storage.Get(context.Background(), key)
		if err != nil || entry == nil {
			t.Fatalf("%s: %v", key, err)
		}
		var got map[string]any
		if err := json.Unmarshal(entry.Value, &got); err != nil {
			t.Fatal(err)
		}
		missingFields(t, key, want, got)
	}
}

// missingFields reports fields of the fixture that a fresh write no longer
// produces: a rename or removal that would strand data written by v1.
func missingFields(t *testing.T, at string, want, got map[string]any) {
	t.Helper()
	for field, wantValue := range want {
		gotValue, ok := got[field]
		if !ok {
			t.Errorf("%s: field %q is no longer written", at, field)
			continue
		}
		if w, ok := wantValue.(map[string]any); ok {
			if g, ok := gotValue.(map[string]any); ok {
				missingFields(t, at+"."+field, w, g)
			}
		}
	}
}
