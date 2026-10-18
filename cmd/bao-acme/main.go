// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"

	"github.com/torstei/bao-acme/internal/backend"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		hclog.New(&hclog.LoggerOptions{}).Error("parsing flags", "error", err)
		os.Exit(1)
	}

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(apiClientMeta.GetTLSConfig()),
	}); err != nil {
		hclog.New(&hclog.LoggerOptions{}).Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
