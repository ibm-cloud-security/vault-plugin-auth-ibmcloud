package iam_plugin

import (
	"context"
	"errors"
	"github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
	"sync"
	"time"
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
	providerLock      sync.RWMutex
	provider          *oidc.Provider
	providerCtx       context.Context
	providerCtxCancel context.CancelFunc
	httpClient        *http.Client
	adminTokenLock    sync.RWMutex
	adminToken        string
	adminTokenExpiry  time.Time
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
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
				pathConfig(b),
			},
			pathsRole(b),
		),
		Clean:      b.cleanup,
		Invalidate: b.invalidate,
	}
	return b
}

func (b *icAuthBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	}
}

func (b *icAuthBackend) reset() {
	b.adminTokenLock.Lock()
	unlockFunc := b.adminTokenLock.Unlock
	defer func() { unlockFunc() }()

	b.adminTokenExpiry = time.Now()
	b.adminToken = ""
}

func (b *icAuthBackend) cleanup(_ context.Context) {
	b.providerLock.Lock()
	if b.providerCtxCancel != nil {
		b.providerCtxCancel()
	}
	b.providerLock.Unlock()
}

func (b *icAuthBackend) getProvider() (*oidc.Provider, error) {
	b.providerLock.RLock()
	unlockFunc := b.providerLock.RUnlock
	defer func() { unlockFunc() }()

	if b.provider != nil {
		return b.provider, nil
	}

	b.providerLock.RUnlock()
	b.providerLock.Lock()
	unlockFunc = b.providerLock.Unlock

	if b.provider != nil {
		return b.provider, nil
	}

	provider, err := oidc.NewProvider(b.providerCtx, iamIdentityEndpointDefault)
	if err != nil {
		return nil, errwrap.Wrapf("error creating provider with given values: {{err}}", err)
	}

	b.provider = provider
	return provider, nil
}

/**
Verifies an IBM Cloud IAM token. If successful, it will return a tokenInfo
with relevant items contained in the token.
*/
func (b *icAuthBackend) verifyToken(ctx context.Context, token string) (*tokenInfo, *logical.Response) {
	// verify the token
	provider, err := b.getProvider()
	if err != nil {
		return nil, logical.ErrorResponse("unable to successfully parse all claims from token: %s", err)
	}

	oidcConfig := &oidc.Config{
		SkipClientIDCheck: true,
	}
	verifier := provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, logical.ErrorResponse("an error occurred verifying the token %s", err)
	}

	// Get the IAM access token claims we are interested in
	iamAccessTokenClaims := iamAccessTokenClaims{}
	if err := idToken.Claims(&iamAccessTokenClaims); err != nil {
		return nil, logical.ErrorResponse("unable to successfully parse all claims from token: %s", err)
	}

	return &tokenInfo{
		IAMid:   iamAccessTokenClaims.IAMID,
		Subject: idToken.Subject,
		Expiry:  idToken.Expiry,
	}, nil

}

func (b *icAuthBackend) getAdminToken(ctx context.Context, s logical.Storage) (string, error) {
	b.adminTokenLock.RLock()
	unlockFunc := b.adminTokenLock.RUnlock
	defer func() { unlockFunc() }()
	if b.adminToken != "" && (time.Until(b.adminTokenExpiry).Minutes() > adminTokenRenewBeforeExpirationMinutes) {
		return b.adminToken, nil
	}
	b.adminTokenLock.RUnlock()

	b.adminTokenLock.Lock()
	unlockFunc = b.adminTokenLock.Unlock
	if b.adminToken != "" && (time.Until(b.adminTokenExpiry).Minutes() > adminTokenRenewBeforeExpirationMinutes) {
		return b.adminToken, nil
	}

	config, err := b.config(ctx, s)
	if err != nil {
		b.Logger().Error("failed to load configuration")
		return "", err
	}

	if config == nil || config.APIKey == "" {
		return "", errors.New("no API key was set in the configuration. Token login requires the auth plugin to be configured with an API key")
	}

	token, err := obtainToken(b.httpClient, iamIdentityEndpointDefault, config.APIKey)
	if err != nil {
		b.Logger().Error("failed to obtain the access token using the configured API key configuration", "error", err)
		return "", err
	}
	adminTokenInfo, resp := b.verifyToken(ctx, token)
	if resp != nil {
		return "", resp.Error()
	}
	b.adminToken = token
	b.adminTokenExpiry = adminTokenInfo.Expiry
	return b.adminToken, nil
}

const backendHelp = `
The IBM Cloud backend plugin allows authentication for IBM Public Cloud.
`
