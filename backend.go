package ibmcloudauth

import (
	"context"
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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
type ibmCloudAuthBackend struct {
	*framework.Backend
	adminTokenLock   sync.RWMutex
	adminToken       string
	adminTokenExpiry time.Time
	iamHelperLock    sync.RWMutex
	iamHelper        iamHelper
}

func Backend(c *logical.BackendConfig) *ibmCloudAuthBackend {
	b := &ibmCloudAuthBackend{}
	b.iamHelper = new(ibmCloudHelper)
	b.iamHelper.Init()

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

func (b *ibmCloudAuthBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case "config":
		b.reset()
	}
}

func (b *ibmCloudAuthBackend) reset() {
	b.adminTokenLock.Lock()
	unlockFunc := b.adminTokenLock.Unlock
	defer func() { unlockFunc() }()

	b.adminTokenExpiry = time.Now()
	b.adminToken = ""
}

func (b *ibmCloudAuthBackend) cleanup(_ context.Context) {
	b.iamHelper.Cleanup()
}

func (b *ibmCloudAuthBackend) getAdminToken(ctx context.Context, s logical.Storage) (string, error) {
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

	token, err := b.iamHelper.ObtainToken(config.APIKey)
	if err != nil {
		b.Logger().Error("failed to obtain the access token using the configured API key configuration", "error", err)
		return "", err
	}
	adminTokenInfo, resp := b.iamHelper.VerifyToken(ctx, token)
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
