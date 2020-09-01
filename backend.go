package iam_plugin

import (
	"context"
	"github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
	"sync"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// IBM Cloud Auth Backend
type icAuthBackend struct {
	*framework.Backend
	l                 sync.RWMutex
	provider          *oidc.Provider
	providerCtx       context.Context
	providerCtxCancel context.CancelFunc
	httpClient        *http.Client
}

func Backend(c *logical.BackendConfig) *icAuthBackend {
	b := &icAuthBackend{}
	b.providerCtx, b.providerCtxCancel = context.WithCancel(context.Background())
	b.httpClient = cleanhttp.DefaultPooledClient()

	b.Backend = &framework.Backend{
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential, // This means it's an auth plugin
		Help:        backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"}, // the '/login' path in not authenticated
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
			},
			pathsRole(b),
		),
		Clean: b.cleanup,
	}
	return b
}

func (b *icAuthBackend) cleanup(_ context.Context) {
	b.l.Lock()
	if b.providerCtxCancel != nil {
		b.providerCtxCancel()
	}
	b.l.Unlock()
}

func (b *icAuthBackend) getProvider() (*oidc.Provider, error) {
	b.l.RLock()
	unlockFunc := b.l.RUnlock
	defer func() { unlockFunc() }()

	if b.provider != nil {
		return b.provider, nil
	}

	b.l.RUnlock()
	b.l.Lock()
	unlockFunc = b.l.Unlock

	if b.provider != nil {
		return b.provider, nil
	}

	provider, err := oidc.NewProvider(b.providerCtx, iamIdentityEndpointDefault)
	if err != nil {
		return nil, errwrap.Wrapf("error creating provider with given values: {{err}}", err)
	}

	if err != nil {
		return nil, err
	}

	b.provider = provider
	return provider, nil
}

const backendHelp = `
The IBM Cloud backend plugin allows authentication for IBM Public Cloud.
`
