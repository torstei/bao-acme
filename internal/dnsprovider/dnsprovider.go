// SPDX-License-Identifier: MPL-2.0

// Package dnsprovider builds lego DNS-01 providers from stored settings.
// Each provider is constructed from its typed config: lego's environment
// variables and its environment-reading defaults are never used.
package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/challenge"
)

// Field is one setting of a provider.
type Field struct {
	Name        string
	Description string
	// Secret fields are write-only.
	Secret   bool
	Required bool
}

// Settings are a provider's stored values, by field name.
type Settings map[string]string

// Common are the settings every provider takes. Zero means the provider's
// default.
type Common struct {
	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
}

// Spec describes one provider.
type Spec struct {
	Name        string
	Description string
	Fields      []Field
	// Egress says where the provider connects, for allow-listing.
	Egress string
	// HTTP providers take the engine's HTTP client, so they use its proxy.
	HTTP bool

	check  func(Settings) error
	build  func(Settings, Common, *http.Client) (challenge.Provider, error)
	remove func(context.Context, Settings, Common, *http.Client, challengeRecord) (bool, error)
}

var specs = map[string]*Spec{}

func register(s *Spec) {
	specs[s.Name] = s
}

// Lookup returns the provider called name.
func Lookup(name string) (*Spec, bool) {
	s, ok := specs[name]
	return s, ok
}

// Names lists the providers.
func Names() []string {
	names := make([]string, 0, len(specs))
	for n := range specs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// AllFields returns every provider field by name, with a description that
// says which providers use it.
func AllFields() map[string]Field {
	out := map[string]Field{}
	for _, name := range Names() {
		for _, f := range specs[name].Fields {
			desc := name + ": " + f.Description
			if prev, ok := out[f.Name]; ok {
				desc = prev.Description + " " + desc
			}
			f.Description = desc
			out[f.Name] = f
		}
	}
	return out
}

// Field returns the provider's field called name.
func (s *Spec) Field(name string) (Field, bool) {
	i := slices.IndexFunc(s.Fields, func(f Field) bool { return f.Name == name })
	if i < 0 {
		return Field{}, false
	}
	return s.Fields[i], true
}

// Build validates settings and constructs the provider. It makes no
// network calls.
func (s *Spec) Build(settings Settings, common Common, httpClient *http.Client) (challenge.Provider, error) {
	var missing []string
	for _, f := range s.Fields {
		if f.Required && settings[f.Name] == "" {
			missing = append(missing, f.Name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%s needs %s", s.Name, strings.Join(missing, ", "))
	}
	for k := range settings {
		if _, ok := s.Field(k); !ok {
			return nil, fmt.Errorf("%s has no setting %q", s.Name, k)
		}
	}
	if s.check != nil {
		if err := s.check(settings); err != nil {
			return nil, fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	if common.TTL < 0 || common.PropagationTimeout < 0 || common.PollingInterval < 0 {
		return nil, errors.New("ttl, propagation_timeout and polling_interval cannot be negative")
	}
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	return s.build(settings, common, httpClient)
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
