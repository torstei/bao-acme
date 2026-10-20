// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/torstei/bao-acme/internal/cert"
	"github.com/torstei/bao-acme/internal/testcerts"
)

func (e *managedEnv) defineReusing(name string, names ...string) {
	e.t.Helper()
	e.ok(logical.CreateOperation, "certs/"+name, map[string]any{
		"names": strings.Join(names, ","), "dns": "bind", "reuse_key": true,
	})
}

func (e *managedEnv) renewTo(name string, version int, data map[string]any) *certVersion {
	e.t.Helper()
	e.ok(logical.UpdateOperation, "certs/"+name+"/renew", data)
	e.waitFor(name, "the renewal", hasVersion(version))
	return e.current(name)
}

func spkiOf(v *certVersion) string { return v.Description.SPKISHA256 }

func TestReuseKeyKeepsThePublicKey(t *testing.T) {
	e := newManagedEnv(t)
	e.defineReusing("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	v1 := e.current("www")

	v2 := e.renewTo("www", 2, nil)
	if spkiOf(v2) != spkiOf(v1) || v2.Privkey != v1.Privkey || v2.Description.SHA256 == v1.Description.SHA256 {
		t.Fatalf("renewal with reuse_key: same key %v, new certificate %v", spkiOf(v2) == spkiOf(v1), v2.Description.SHA256 != v1.Description.SHA256)
	}

	v3 := e.renewTo("www", 3, map[string]any{"rotate_key": true})
	if spkiOf(v3) == spkiOf(v2) {
		t.Fatal("rotate_key kept the key")
	}
	if m, _ := loadMeta(context.Background(), e.storage, "www"); m.Issuance.RotateKey {
		t.Error("rotate_key still requested after the renewal")
	}
	if v4 := e.renewTo("www", 4, nil); spkiOf(v4) != spkiOf(v3) {
		t.Error("the key after a rotation is not reused")
	}

	info := e.ok(logical.ReadOperation, "certs/www/info", nil)
	if info.Data["definition"].(map[string]any)["reuse_key"] != true {
		t.Errorf("definition = %v", info.Data["definition"])
	}
}

func TestWithoutReuseKeyEveryRenewalHasANewKey(t *testing.T) {
	e := newManagedEnv(t)
	e.define("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	v1 := e.current("www")
	if v2 := e.renewTo("www", 2, nil); spkiOf(v2) == spkiOf(v1) {
		t.Error("a renewal without reuse_key kept the key")
	}
}

func TestReuseKeyKeepsAnImportedKey(t *testing.T) {
	e := newManagedEnv(t)
	imported := testcerts.New(t, testcerts.Options{Names: []string{"www.example.test"}})
	e.imp("www", imported)
	e.defineReusing("www", "www.example.test")

	v2 := e.renewTo("www", 2, nil)
	if v2.Privkey != imported.Privkey || v2.Source != "acme:le" {
		t.Errorf("the imported key was not carried over: source %s", v2.Source)
	}
}

func TestKeyTypeChangeMeansANewKey(t *testing.T) {
	e := newManagedEnv(t)
	e.defineReusing("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))

	e.ok(logical.UpdateOperation, "certs/www", map[string]any{"key_type": "rsa-2048"})
	e.waitFor("www", "the certificate with the new key type", hasVersion(2))
	if got := e.current("www").Description.KeyType; got != "rsa-2048" {
		t.Errorf("key_type = %s", got)
	}
}

func TestDestroyByFingerprintAndNoReuseOfADestroyedKey(t *testing.T) {
	e := newManagedEnv(t)
	e.defineReusing("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	v2 := e.renewTo("www", 2, nil)
	shared := spkiOf(v2)

	resp := e.ok(logical.UpdateOperation, "certs/www/destroy", map[string]any{"versions": "1"})
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "version(s) 2 still hold the same key") {
		t.Errorf("warnings = %v", resp.Warnings)
	}
	if v3 := e.renewTo("www", 3, nil); spkiOf(v3) == shared {
		t.Error("reused a key one of whose versions was destroyed")
	}

	e.renewTo("www", 4, nil)
	key4 := spkiOf(e.current("www"))
	resp = e.ok(logical.UpdateOperation, "certs/www/destroy", map[string]any{"spki_sha256": key4})
	if len(resp.Warnings) != 0 {
		t.Errorf("warnings after destroying everywhere = %v", resp.Warnings)
	}
	for _, n := range []int{3, 4} {
		if v, _ := loadVersion(context.Background(), e.storage, "www", n); !v.destroyed() {
			t.Errorf("version %d still holds the destroyed key", n)
		}
	}

	e.periodic()
	e.waitFor("www", "a certificate replacing the destroyed key", hasVersion(5))
	if spkiOf(e.current("www")) == key4 {
		t.Error("the destroyed key came back")
	}

	e.fails(logical.UpdateOperation, "certs/www/destroy", nil, "either versions or spki_sha256")
	e.fails(logical.UpdateOperation, "certs/www/destroy", map[string]any{"versions": "1", "spki_sha256": key4}, "either versions or spki_sha256")
	e.fails(logical.UpdateOperation, "certs/www/destroy", map[string]any{"spki_sha256": strings.Repeat("0", 64)}, "no version holds")
}

func TestKeyDestroyedDuringAnAttemptIsNotStored(t *testing.T) {
	e := newManagedEnv(t)
	ctx := context.Background()
	e.defineReusing("www", "www.example.test")
	e.waitFor("www", "the certificate", hasVersion(1))
	e.b.issuer.stop()

	if err := e.b.requestRenewal(ctx, e.storage, "le", "www", false); err != nil {
		t.Fatal(err)
	}
	claim, err := e.b.claimIssuance(ctx, e.storage, "www")
	if err != nil || claim == nil || claim.reusedFrom != 1 {
		t.Fatalf("claim = %+v, %v", claim, err)
	}
	bundle, err := e.b.obtain(ctx, e.storage, "www", claim)
	if err != nil {
		t.Fatal(err)
	}

	e.ok(logical.UpdateOperation, "certs/www/destroy", map[string]any{"spki_sha256": spkiOf(e.current("www"))})
	if i := e.inflight("www"); i != nil && i.Privkey != "" {
		t.Error("destroying the key left it in the in-flight entry")
	}

	stored, err := e.b.recordIssuance(ctx, e.storage, "www", &claim.spec, bundle, nil, attemptRecord{Reason: claim.reason})
	if stored || err == nil {
		t.Fatalf("stored a certificate for a destroyed key: %v, %v", stored, err)
	}
	if m, _ := loadMeta(ctx, e.storage, "www"); m.CurrentVersion != 1 || !strings.Contains(m.Issuance.LastError, "destroyed") {
		t.Errorf("meta = %+v, issuance = %+v", m, m.Issuance)
	}
}

func TestSPKISHA256MatchesTheDescription(t *testing.T) {
	c := testcerts.New(t, testcerts.Options{})
	b, err := cert.Parse(c.Fullchain, c.Privkey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got, err := cert.SPKISHA256(c.Key.Public())
	if err != nil || got != b.Describe().SPKISHA256 {
		t.Errorf("SPKISHA256 = %s, description %s, %v", got, b.Describe().SPKISHA256, err)
	}
}
