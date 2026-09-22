package registry

import (
	"github.com/MamreTek/cert-harbor/internal/providers"
	"github.com/MamreTek/cert-harbor/internal/providers/alibaba"
	"github.com/MamreTek/cert-harbor/internal/providers/aws"
	"github.com/MamreTek/cert-harbor/internal/providers/cloudflare"
	"github.com/MamreTek/cert-harbor/internal/providers/tencent"
)

func New(fixturePath string) map[providers.Provider]providers.Adapter {
	return map[providers.Provider]providers.Adapter{
		providers.AlibabaCloud: alibaba.New(fixturePath),
		providers.Tencent:      tencent.New(fixturePath),
		providers.AWS:          aws.New(fixturePath),
		providers.Cloudflare:   cloudflare.New(fixturePath),
	}
}
