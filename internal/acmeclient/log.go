// SPDX-License-Identifier: MPL-2.0

package acmeclient

import (
	"context"
	"log/slog"
	"sync"

	legolog "github.com/go-acme/lego/v5/log"
	hclog "github.com/hashicorp/go-hclog"
)

var setLoggerOnce sync.Once

// SetLogger routes lego's logging to l. lego's logger is process-wide, so
// only the first call has an effect. Without it lego writes to stdout.
func SetLogger(l hclog.Logger) {
	setLoggerOnce.Do(func() {
		legolog.SetDefault(slog.New(&hclogHandler{l: l.Named("lego")}))
	})
}

type hclogHandler struct {
	l     hclog.Logger
	attrs []any
	group string
}

func (h *hclogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.l.GetLevel() <= toHclogLevel(level)
}

func (h *hclogHandler) Handle(_ context.Context, r slog.Record) error {
	args := append([]any(nil), h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		args = append(args, h.key(a.Key), a.Value.Any())
		return true
	})
	h.l.Log(toHclogLevel(r.Level), r.Message, args...)
	return nil
}

func (h *hclogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append([]any(nil), h.attrs...)
	for _, a := range attrs {
		next.attrs = append(next.attrs, h.key(a.Key), a.Value.Any())
	}
	return &next
}

func (h *hclogHandler) WithGroup(name string) slog.Handler {
	next := *h
	next.group = h.key(name)
	return &next
}

func (h *hclogHandler) key(k string) string {
	if h.group == "" {
		return k
	}
	return h.group + "." + k
}

// lego logs every request at Info, contact addresses included, which is
// debug-level detail for OpenBao's log.
func toHclogLevel(l slog.Level) hclog.Level {
	switch {
	case l >= slog.LevelError:
		return hclog.Error
	case l >= slog.LevelWarn:
		return hclog.Warn
	default:
		return hclog.Debug
	}
}
