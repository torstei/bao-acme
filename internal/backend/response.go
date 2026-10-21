// SPDX-License-Identifier: MPL-2.0

package backend

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// HandleRequest leaves out of every response the values that do not
// apply: zero times and empty strings, at any depth. bao would otherwise
// print a zero time as year 1, and an empty string as nothing at all.
func (b *backend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	resp, err := b.Backend.HandleRequest(ctx, req)
	if resp != nil && !resp.IsError() {
		omitEmpty(resp.Data)
	}
	return resp, err
}

func omitEmpty(data map[string]any) {
	for k, v := range data {
		if empty(v) {
			delete(data, k)
		}
	}
}

func empty(v any) bool {
	switch v := v.(type) {
	case string:
		return v == ""
	case time.Time:
		return v.IsZero()
	case map[string]any:
		omitEmpty(v)
	case []map[string]any:
		for _, m := range v {
			omitEmpty(m)
		}
	case []any:
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				omitEmpty(m)
			}
		}
	}
	return false
}
