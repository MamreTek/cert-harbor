package tencent

import "github.com/MamreTek/cert-harbor/internal/providers"

func New(fixturePath string) providers.Adapter {
	return providers.NewFixtureAdapter(providers.Tencent, fixturePath, providers.Capabilities{
		Provider:             providers.Tencent,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Use a CAM user or role with read-only DNSPod and SSL Certificate permissions.",
		SupportedSourceTypes: []string{"dns_zone", "certificate"},
	})
}
