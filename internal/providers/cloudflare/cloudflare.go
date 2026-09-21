package cloudflare

import "github.com/MamreTek/cert-harbor/internal/providers"

func New(fixturePath string) providers.Adapter {
	return providers.NewFixtureAdapter(providers.Cloudflare, fixturePath, providers.Capabilities{
		Provider:             providers.Cloudflare,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Use a scoped API token with Zone:Read and SSL/TLS:Read permissions.",
		SupportedSourceTypes: []string{"zone", "certificate"},
	})
}
