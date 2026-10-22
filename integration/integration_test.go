// SPDX-License-Identifier: MPL-2.0

//go:build integration

// Package integration runs the plugin inside a real OpenBao in Docker.
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/docker"

	"github.com/torstei/bao-acme/internal/testcerts"
)

const (
	pluginName = "bao-acme"
	mount      = "certificates"
	rootToken  = "root"
)

// Override with BAO_IMAGE, e.g. BAO_IMAGE=quay.io/openbao/openbao:2.8.0.
const defaultImage = "quay.io/openbao/openbao:2.7.0"

// Audit devices can only be declared in configuration, not enabled over the API.
const serverConfig = `
plugin_directory = "/openbao/plugins"

audit "file" "stdout" {
  options {
    file_path = "stdout"
  }
}
`

type cluster struct {
	t      *testing.T
	client *api.Client
	logs   *logBuffer
}

type logBuffer struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuffer) add(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, line)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func buildPlugin(t *testing.T) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), pluginName)
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "../cmd/"+pluginName)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building plugin: %v\n%s", err, b)
	}
	bin, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

func startOpenBao(t *testing.T) *cluster {
	t.Helper()
	bin := buildPlugin(t)

	repo, tag, _ := strings.Cut(defaultImage, ":")
	if img := os.Getenv("BAO_IMAGE"); img != "" {
		repo, tag, _ = strings.Cut(img, ":")
	}

	files := docker.NewBuildContext()
	files["plugins/"+pluginName] = &docker.FileContents{Data: bin, Mode: 0o755, UID: 100, GID: 1000}
	files["config/test.hcl"] = docker.PathContentsFromString(serverConfig)

	logs := &logBuffer{}
	runner, err := docker.NewServiceRunner(docker.RunOptions{
		ImageRepo:     repo,
		ImageTag:      tag,
		ContainerName: "bao-acme-it",
		Cmd:           []string{"server", "-dev"},
		Env:           []string{"BAO_DEV_ROOT_TOKEN_ID=" + rootToken},
		Ports:         []string{"8200/tcp"},
		WriteInto:     map[string]docker.BuildContext{"/openbao": files},
		LogConsumer:   logs.add,
	})
	if err != nil {
		t.Fatalf("docker: %v", err)
	}

	var client *api.Client
	svc, err := runner.StartService(context.Background(), func(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
		cfg := api.DefaultConfig()
		cfg.Address = fmt.Sprintf("http://%s:%d", host, port)
		c, err := api.NewClient(cfg)
		if err != nil {
			return nil, err
		}
		c.SetToken(rootToken)
		health, err := c.Sys().HealthWithContext(ctx)
		if err != nil {
			return nil, err
		}
		if !health.Initialized || health.Sealed {
			return nil, errors.New("not ready")
		}
		client = c
		return docker.NewServiceURLParse(cfg.Address)
	})
	if err != nil {
		t.Fatalf("starting OpenBao: %v\n%s", err, logs)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("OpenBao log:\n%s", logs)
		}
		svc.Cleanup()
	})

	ctx := context.Background()
	sum := sha256.Sum256(bin)
	if err := client.Sys().RegisterPluginWithContext(ctx, &api.RegisterPluginInput{
		Name:    pluginName,
		Type:    api.PluginTypeSecrets,
		Command: pluginName,
		SHA256:  hex.EncodeToString(sum[:]),
	}); err != nil {
		t.Fatalf("registering plugin: %v", err)
	}
	if err := client.Sys().MountWithContext(ctx, mount, &api.MountInput{Type: pluginName}); err != nil {
		t.Fatalf("mounting plugin: %v", err)
	}
	return &cluster{t: t, client: client, logs: logs}
}

func (c *cluster) tokenFor(policy string) *api.Client {
	c.t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("p%d", time.Now().UnixNano())
	if err := c.client.Sys().PutPolicyWithContext(ctx, name, policy); err != nil {
		c.t.Fatal(err)
	}
	secret, err := c.client.Auth().Token().CreateWithContext(ctx, &api.TokenCreateRequest{Policies: []string{name}})
	if err != nil {
		c.t.Fatal(err)
	}
	clone, err := c.client.Clone()
	if err != nil {
		c.t.Fatal(err)
	}
	clone.SetToken(secret.Auth.ClientToken)
	return clone
}

func importCert(t *testing.T, client *api.Client, name string, chain testcerts.Chain) *api.Secret {
	t.Helper()
	s, err := client.Logical().Write(mount+"/accounts/team-a/certs/"+name+"/import", map[string]any{
		"fullchain": chain.Fullchain,
		"privkey":   chain.Privkey,
	})
	if err != nil {
		t.Fatalf("import %s: %v", name, err)
	}
	return s
}

func read(t *testing.T, client *api.Client, path string) *api.Secret {
	t.Helper()
	s, err := client.Logical().Read(mount + "/" + path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if s == nil {
		t.Fatalf("read %s: not found", path)
	}
	return s
}

func wantForbidden(t *testing.T, err error, what string) {
	t.Helper()
	var re *api.ResponseError
	if !errors.As(err, &re) || re.StatusCode != http.StatusForbidden {
		t.Errorf("%s: err = %v, want 403", what, err)
	}
}

func list(t *testing.T, client *api.Client, covers string) []string {
	t.Helper()
	req := client.NewRequest("LIST", "/v1/"+mount+"/accounts/team-a/certs")
	if covers != "" {
		req.Params.Set("covers", covers)
	}
	resp, err := client.RawRequestWithContext(context.Background(), req)
	if resp != nil {
		defer resp.Body.Close()
	}
	var re *api.ResponseError
	if errors.As(err, &re) && re.StatusCode == http.StatusNotFound {
		return nil
	}
	if err != nil {
		t.Fatalf("list covers=%q: %v", covers, err)
	}
	s, err := api.ParseSecret(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, k := range s.Data["keys"].([]any) {
		keys = append(keys, k.(string))
	}
	return keys
}

func TestIntegration(t *testing.T) {
	c := startOpenBao(t)
	ctx := context.Background()

	wildcard := testcerts.New(t, testcerts.Options{Names: []string{"*.example.com", "example.com"}})
	other := testcerts.New(t, testcerts.Options{Names: []string{"example.org"}})

	for _, account := range []string{"team-a", "team-b"} {
		if _, err := c.client.Logical().Write(mount+"/config/accounts/"+account, map[string]any{}); err != nil {
			t.Fatalf("creating account %s: %v", account, err)
		}
	}

	t.Run("import is idempotent", func(t *testing.T) {
		first := importCert(t, c.client, "wildcard.example.com", wildcard)
		if first.Data["written"] != true {
			t.Fatalf("first import: %v", first.Data)
		}
		again := importCert(t, c.client, "wildcard.example.com", wildcard)
		if again.Data["written"] != false || fmt.Sprint(again.Data["version"]) != "1" {
			t.Fatalf("second import: %v", again.Data)
		}
		importCert(t, c.client, "example.org", other)
	})

	t.Run("read returns the key, info does not", func(t *testing.T) {
		full := read(t, c.client, "accounts/team-a/certs/wildcard.example.com")
		if full.Data["privkey"] != wildcard.Privkey {
			t.Error("privkey differs from the imported one")
		}
		info := read(t, c.client, "accounts/team-a/certs/wildcard.example.com/info")
		if _, ok := info.Data["privkey"]; ok {
			t.Error("info returned privkey")
		}
		if info.Data["key_type"] != "ecdsa-p256" || info.Data["issuer"] != "Test CA T1" {
			t.Errorf("info = %v", info.Data)
		}
	})

	t.Run("policies separate key and description", func(t *testing.T) {
		monitoring := c.tokenFor(`path "certificates/accounts/team-a/certs/+/info" { capabilities = ["read"] }`)
		consumer := c.tokenFor(`path "certificates/accounts/team-a/certs/example.org" { capabilities = ["read"] }`)
		importer := c.tokenFor(`path "certificates/accounts/team-a/certs/+/import" { capabilities = ["update"] }`)

		read(t, monitoring, "accounts/team-a/certs/wildcard.example.com/info")
		_, err := monitoring.Logical().Read(mount + "/accounts/team-a/certs/wildcard.example.com")
		wantForbidden(t, err, "monitoring reading the key")

		if read(t, consumer, "accounts/team-a/certs/example.org").Data["privkey"] != other.Privkey {
			t.Error("consumer got the wrong key")
		}
		_, err = consumer.Logical().Read(mount + "/accounts/team-a/certs/wildcard.example.com")
		wantForbidden(t, err, "consumer reading another certificate")

		renewed := testcerts.New(t, testcerts.Options{Names: []string{"example.org"}})
		if s := importCert(t, importer, "example.org", renewed); fmt.Sprint(s.Data["version"]) != "2" {
			t.Errorf("importer's import: %v", s.Data)
		}
		_, err = importer.Logical().Read(mount + "/accounts/team-a/certs/example.org")
		wantForbidden(t, err, "importer reading the key")

		by := read(t, c.client, "accounts/team-a/certs/example.org/info").Data["imported_by"].(map[string]any)
		if !strings.HasPrefix(by["display_name"].(string), "token") {
			t.Errorf("imported_by = %v", by)
		}
	})

	t.Run("accounts are kept apart", func(t *testing.T) {
		teamB := c.tokenFor(`path "certificates/accounts/team-b/*" { capabilities = ["create", "read", "update", "delete", "list"] }`)

		_, err := teamB.Logical().Read(mount + "/accounts/team-a/certs/example.org")
		wantForbidden(t, err, "team B reading team A's path")

		if s, err := teamB.Logical().Read(mount + "/accounts/team-b/certs/example.org"); err != nil || s != nil {
			t.Errorf("team B reached team A's certificate through its own path: %v, %v", s, err)
		}
		teamAKey := read(t, c.client, "accounts/team-a/certs/example.org").Data["privkey"]
		own := testcerts.New(t, testcerts.Options{Names: []string{"example.org"}})
		if _, err := teamB.Logical().Write(mount+"/accounts/team-b/certs/example.org/import", map[string]any{
			"fullchain": own.Fullchain, "privkey": own.Privkey,
		}); err != nil {
			t.Fatalf("team B using the same name as team A: %v", err)
		}
		if got := read(t, teamB, "accounts/team-b/certs/example.org").Data["privkey"]; got != own.Privkey {
			t.Error("team B does not read its own certificate")
		}
		if got := read(t, c.client, "accounts/team-a/certs/example.org").Data["privkey"]; got != teamAKey {
			t.Error("team B's certificate replaced team A's")
		}
		if _, err := teamB.Logical().Delete(mount + "/accounts/team-b/certs/example.org"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("list with covers", func(t *testing.T) {
		if got := strings.Join(list(t, c.client, ""), ","); got != "example.org,wildcard.example.com" {
			t.Errorf("list = %q", got)
		}
		if got := strings.Join(list(t, c.client, "www.example.com"), ","); got != "wildcard.example.com" {
			t.Errorf("covers www.example.com = %q", got)
		}
		if got := list(t, c.client, "a.b.example.com"); len(got) != 0 {
			t.Errorf("covers a.b.example.com = %v", got)
		}
	})

	t.Run("account key stays inside", func(t *testing.T) {
		created, err := c.client.Logical().Write(mount+"/config/accounts/le-staging", map[string]any{
			"directory_url": "letsencrypt-staging",
			"email":         "ops@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		if created.Data["directory_url"] != "https://acme-staging-v02.api.letsencrypt.org/directory" || created.Data["registered"] != false {
			t.Errorf("created = %v", created.Data)
		}
		if _, ok := read(t, c.client, "config/accounts/le-staging").Data["private_key"]; ok {
			t.Error("account read returned the private key")
		}
	})

	t.Run("proxy credentials stay inside", func(t *testing.T) {
		written, err := c.client.Logical().Write(mount+"/config/network", map[string]any{
			"proxy_url": "http://bao:proxy-s3cret@proxy.example:3128",
		})
		if err != nil {
			t.Fatal(err)
		}
		readBack := read(t, c.client, "config/network")
		for _, s := range []*api.Secret{written, readBack} {
			if s.Data["proxy_url"] != "http://proxy.example:3128" || s.Data["proxy_credentials_set"] != true {
				t.Errorf("network = %v", s.Data)
			}
		}
	})

	t.Run("DNS credentials stay inside", func(t *testing.T) {
		if _, err := c.client.Logical().Write(mount+"/accounts/team-a/dns/domeneshop", map[string]any{
			"type":       "domeneshop",
			"api_token":  "dns-tok3n",
			"api_secret": "dns-s3cret",
		}); err != nil {
			t.Fatal(err)
		}
		got := read(t, c.client, "accounts/team-a/dns/domeneshop").Data
		if got["api_token_set"] != true || got["api_secret_set"] != true {
			t.Errorf("dns = %v", got)
		}
		if s := fmt.Sprint(got); strings.Contains(s, "dns-tok3n") || strings.Contains(s, "dns-s3cret") {
			t.Errorf("credentials returned: %s", s)
		}
	})

	t.Run("background issuance records its outcome", func(t *testing.T) {
		writes := map[string]map[string]any{
			"config/accounts/unreachable": {
				"directory_url":           "https://127.0.0.1:1/directory",
				"terms_of_service_agreed": true,
			},
			"accounts/unreachable/dns/bind": {"type": "dnsupdate", "nameserver": "127.0.0.1"},
			"accounts/unreachable/certs/background": {
				"names": "www.example.test",
				"dns":   "bind",
			},
		}
		for _, path := range []string{"config/accounts/unreachable", "accounts/unreachable/dns/bind", "accounts/unreachable/certs/background"} {
			if _, err := c.client.Logical().Write(mount+"/"+path, writes[path]); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}

		var issuance map[string]any
		for range 100 {
			issuance = read(t, c.client, "accounts/unreachable/certs/background/info").Data["issuance"].(map[string]any)
			if fmt.Sprint(issuance["failures"]) == "1" {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if fmt.Sprint(issuance["failures"]) != "1" || !strings.Contains(fmt.Sprint(issuance["last_error"]), "127.0.0.1:1") {
			t.Fatalf("issuance = %v", issuance)
		}
		if v, ok := issuance["last_success_time"]; ok {
			t.Errorf("a certificate never issued shows last_success_time %v", v)
		}

		status := read(t, c.client, "accounts/unreachable/certs/background/status").Data
		attempts, _ := status["attempts"].([]any)
		if status["state"] != "failing" || len(attempts) != 1 {
			t.Errorf("status = %v", status)
		}
		mountStatus := read(t, c.client, "status").Data
		if counts := mountStatus["counts"].(map[string]any); fmt.Sprint(counts["failing"]) != "1" {
			t.Errorf("mount status = %v", mountStatus)
		}
	})

	t.Run("data survives a plugin reload", func(t *testing.T) {
		if _, err := c.client.Sys().ReloadPluginWithContext(ctx, &api.ReloadPluginInput{Plugin: pluginName}); err != nil {
			t.Fatalf("reload: %v", err)
		}
		var info *api.Secret
		var err error
		for range 50 {
			info, err = c.client.Logical().Read(mount + "/accounts/team-a/certs/example.org/info")
			if err == nil && info != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil || info == nil || fmt.Sprint(info.Data["current_version"]) != "2" {
			t.Fatalf("after reload: %v, %v", info, err)
		}
	})

	t.Run("audit log does not contain keys", func(t *testing.T) {
		logs := c.logs.String()
		if !strings.Contains(logs, `"type":"response"`) {
			t.Fatal("no audit entries in the container log")
		}
		if strings.Contains(logs, "PRIVATE KEY") {
			t.Error("audit log contains a private key in clear text")
		}
		if strings.Contains(logs, "proxy-s3cret") {
			t.Error("audit log contains the proxy password in clear text")
		}
		if strings.Contains(logs, "dns-s3cret") {
			t.Error("audit log contains a DNS credential in clear text")
		}
	})
}
