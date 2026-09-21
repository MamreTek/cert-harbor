package alibaba

import "github.com/MamreTek/cert-harbor/internal/providers"

func New(fixturePath string) providers.Adapter {
	return providers.NewFixtureAdapter(providers.AlibabaCloud, fixturePath, providers.Capabilities{
		Provider:             providers.AlibabaCloud,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Use a RAM user or role with read-only AliDNS and Certificate Management permissions.",
		SupportedSourceTypes: []string{"dns_zone", "certificate"},
	})
}
