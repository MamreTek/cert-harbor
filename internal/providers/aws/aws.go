package aws

import "github.com/MamreTek/cert-harbor/internal/providers"

func New(fixturePath string) providers.Adapter {
	return providers.NewFixtureAdapter(providers.AWS, fixturePath, providers.Capabilities{
		Provider:             providers.AWS,
		Domains:              true,
		Certificates:         true,
		CredentialGuidance:   "Use an IAM role or user limited to read-only Route 53 and ACM actions; ACM is regional.",
		SupportedSourceTypes: []string{"hosted_zone", "acm_certificate"},
	})
}
