// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/testcerts"
)

type harness struct {
	t       *testing.T
	b       *backend
	storage logical.Storage
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	conf := logical.TestBackendConfig()
	conf.StorageView = &logical.InmemStorage{}
	b := New()
	if err := b.Setup(context.Background(), conf); err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, b: b, storage: conf.StorageView}
}

func (h *harness) do(op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
	h.t.Helper()
	return h.b.HandleRequest(context.Background(), &logical.Request{
		Operation:   op,
		Path:        path,
		Data:        data,
		Storage:     h.storage,
		EntityID:    "entity-1",
		DisplayName: "approle-importer",
	})
}

func (h *harness) ok(op logical.Operation, path string, data map[string]any) *logical.Response {
	h.t.Helper()
	resp, err := h.do(op, path, data)
	if err != nil {
		h.t.Fatalf("%s %s: %v", op, path, err)
	}
	if resp != nil && resp.IsError() {
		h.t.Fatalf("%s %s: %v", op, path, resp.Error())
	}
	return resp
}

func (h *harness) fails(op logical.Operation, path string, data map[string]any, want string) {
	h.t.Helper()
	resp, err := h.do(op, path, data)
	msg := ""
	switch {
	case resp != nil && resp.IsError():
		msg = resp.Error().Error()
	case err != nil:
		msg = err.Error()
	default:
		h.t.Fatalf("%s %s succeeded, want error containing %q", op, path, want)
	}
	if !strings.Contains(msg, want) {
		h.t.Fatalf("%s %s: error %q does not contain %q", op, path, msg, want)
	}
}

func (h *harness) imp(name string, c testcerts.Chain) *logical.Response {
	h.t.Helper()
	return h.ok(logical.UpdateOperation, "certs/"+name+"/import", map[string]any{
		"fullchain": c.Fullchain,
		"privkey":   c.Privkey,
	})
}

func TestImportReadInfo(t *testing.T) {
	h := newHarness(t)
	c := testcerts.New(t, testcerts.Options{Names: []string{"www.example.com", "example.com"}})

	resp := h.imp("example.com", c)
	if resp.Data["version"] != 1 || resp.Data["written"] != true {
		t.Fatalf("import: %v", resp.Data)
	}

	read := h.ok(logical.ReadOperation, "certs/example.com", nil)
	if read.Data["privkey"] != c.Privkey || read.Data["fullchain"] != c.Fullchain {
		t.Error("read did not return the imported fullchain and key")
	}
	if !strings.HasPrefix(c.Fullchain, read.Data["certificate"].(string)) {
		t.Error("certificate is not the leaf")
	}

	info := h.ok(logical.ReadOperation, "certs/example.com/info", nil)
	for _, secret := range []string{"privkey", "fullchain", "certificate", "chain"} {
		if _, ok := info.Data[secret]; ok {
			t.Errorf("info returned %s", secret)
		}
	}
	if got := strings.Join(info.Data["names"].([]string), ","); got != "example.com,www.example.com" {
		t.Errorf("names = %q", got)
	}
	if info.Data["source"] != "import" || info.Data["current_version"] != 1 {
		t.Errorf("info = %v", info.Data)
	}
	if by := info.Data["imported_by"].(map[string]any); by["display_name"] != "approle-importer" {
		t.Errorf("imported_by = %v", by)
	}
}

func TestUnchangedImportWritesNothing(t *testing.T) {
	h := newHarness(t)
	c := testcerts.New(t, testcerts.Options{})
	h.imp("a", c)
	resp := h.imp("a", c)
	if resp.Data["version"] != 1 || resp.Data["written"] != false {
		t.Fatalf("second import: %v", resp.Data)
	}
}

func TestMaxVersionsPrunes(t *testing.T) {
	h := newHarness(t)
	for range 5 {
		h.imp("a", testcerts.New(t, testcerts.Options{}))
	}
	info := h.ok(logical.ReadOperation, "certs/a/info", nil)
	versions := info.Data["versions"].(map[string]any)
	if len(versions) != 3 || versions["3"] == nil || versions["5"] == nil || versions["2"] != nil {
		t.Errorf("versions kept = %v", versions)
	}
	if resp, _ := h.do(logical.ReadOperation, "certs/a/versions/2", nil); resp != nil {
		t.Errorf("pruned version still readable: %v", resp.Data)
	}
	h.ok(logical.ReadOperation, "certs/a/versions/3", nil)
}

func TestRollbackKeepsDescriptionAndSurvivesPruning(t *testing.T) {
	h := newHarness(t)
	first := testcerts.New(t, testcerts.Options{Names: []string{"first.example.com"}})
	h.imp("a", first)
	h.imp("a", testcerts.New(t, testcerts.Options{Names: []string{"second.example.com"}}))

	h.ok(logical.UpdateOperation, "certs/a/rollback", map[string]any{"version": 1})
	info := h.ok(logical.ReadOperation, "certs/a/info", nil)
	if info.Data["current_version"] != 1 || info.Data["names"].([]string)[0] != "first.example.com" {
		t.Fatalf("after rollback: %v", info.Data)
	}
	if h.ok(logical.ReadOperation, "certs/a", nil).Data["privkey"] != first.Privkey {
		t.Error("read after rollback did not return version 1")
	}

	h.ok(logical.UpdateOperation, "certs/a/import", map[string]any{
		"fullchain": first.Fullchain, "privkey": first.Privkey, "max_versions": 1,
	})
	h.ok(logical.ReadOperation, "certs/a/versions/1", nil)
	h.ok(logical.ReadOperation, "certs/a/versions/2", nil)

	for range 3 {
		h.imp("a", testcerts.New(t, testcerts.Options{}))
	}
	h.ok(logical.ReadOperation, "certs/a/versions/5", nil)
	if resp, _ := h.do(logical.ReadOperation, "certs/a/versions/1", nil); resp != nil {
		t.Error("version 1 kept after it stopped being current")
	}
}

func TestRollbackRefusals(t *testing.T) {
	h := newHarness(t)
	h.imp("a", testcerts.New(t, testcerts.Options{}))
	h.imp("a", testcerts.New(t, testcerts.Options{}))

	h.fails(logical.UpdateOperation, "certs/a/rollback", map[string]any{"version": 9}, "no version 9")
	h.fails(logical.UpdateOperation, "certs/nope/rollback", map[string]any{"version": 1}, "no certificate")

	h.ok(logical.UpdateOperation, "certs/a/destroy", map[string]any{"versions": "1"})
	h.fails(logical.UpdateOperation, "certs/a/rollback", map[string]any{"version": 1}, "destroyed")

	h.b.now = func() time.Time { return time.Now().Add(200 * 24 * time.Hour) }
	h.fails(logical.UpdateOperation, "certs/a/rollback", map[string]any{"version": 2}, "expired")
}

func TestDestroyKeepsDescription(t *testing.T) {
	h := newHarness(t)
	h.imp("a", testcerts.New(t, testcerts.Options{}))

	h.ok(logical.UpdateOperation, "certs/a/destroy", map[string]any{"versions": []int{1}})
	h.fails(logical.ReadOperation, "certs/a", nil, "destroyed")

	info := h.ok(logical.ReadOperation, "certs/a/info", nil)
	if info.Data["destroyed"] != true || info.Data["sha256"] == "" {
		t.Errorf("info after destroy: %v", info.Data)
	}

	var raw certVersion
	if _, err := getJSON(context.Background(), h.storage, versionKey("a", 1), &raw); err != nil || raw.Privkey != "" {
		t.Errorf("key material still stored: %q, %v", raw.Privkey, err)
	}
}

func TestImportRejectsInvalid(t *testing.T) {
	h := newHarness(t)
	good := testcerts.New(t, testcerts.Options{})
	other := testcerts.New(t, testcerts.Options{})

	resp, err := h.do(logical.UpdateOperation, "certs/a/import", map[string]any{
		"fullchain": good.Fullchain,
		"privkey":   other.Privkey,
	})
	if !errors.Is(err, logical.ErrInvalidRequest) || !strings.Contains(resp.Error().Error(), "does not match") {
		t.Errorf("mismatched key: %v, %v", resp, err)
	}
	h.fails(logical.UpdateOperation, "certs/a/import", map[string]any{
		"fullchain": good.Fullchain, "privkey": good.Privkey, "max_versions": 0,
	}, "at least 1")

	if resp, _ := h.do(logical.ReadOperation, "certs/a", nil); resp != nil {
		t.Error("rejected import was stored")
	}
}

func TestListAndCovers(t *testing.T) {
	h := newHarness(t)
	h.imp("wildcard.example.com", testcerts.New(t, testcerts.Options{Names: []string{"*.example.com"}}))
	h.imp("example.org", testcerts.New(t, testcerts.Options{Names: []string{"example.org"}}))

	all := h.ok(logical.ListOperation, "certs/", nil)
	if got := strings.Join(all.Data["keys"].([]string), ","); got != "example.org,wildcard.example.com" {
		t.Errorf("list = %q", got)
	}

	covering := h.ok(logical.ListOperation, "certs/", map[string]any{"covers": "www.example.com"})
	if got := covering.Data["keys"].([]string); len(got) != 1 || got[0] != "wildcard.example.com" {
		t.Errorf("covers www.example.com = %v", got)
	}
	none := h.ok(logical.ListOperation, "certs/", map[string]any{"covers": "a.b.example.com"})
	if got, ok := none.Data["keys"]; ok {
		t.Errorf("covers a.b.example.com = %v", got)
	}
}

func TestDelete(t *testing.T) {
	h := newHarness(t)
	h.imp("a", testcerts.New(t, testcerts.Options{}))
	h.imp("a", testcerts.New(t, testcerts.Options{}))
	h.ok(logical.DeleteOperation, "certs/a", nil)

	keys, err := h.storage.List(context.Background(), "")
	if err != nil || len(keys) != 0 {
		t.Errorf("storage after delete: %v, %v", keys, err)
	}
}
