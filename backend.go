package ibmcloudauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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

	unlockIAMFunc := b.iamHelperLock.Unlock
	defer func() { unlockIAMFunc() }()

	b.iamHelperLock.Lock()
	if b.iamHelper != nil {
		b.iamHelper.Cleanup()
		b.iamHelper = nil
	}
}

func (b *ibmCloudAuthBackend) cleanup(_ context.Context) {
	b.reset()
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

	iam, resp := b.getIAMHelper(ctx, s)
	if resp != nil {
		b.Logger().Error("failed to retrieve an IAM helper", "error", resp.Error())
		return "", resp.Error()
	}
	token, err := iam.ObtainToken(config.APIKey)
	if err != nil {
		b.Logger().Error("failed to obtain the access token using the configured API key configuration", "error", err)
		return "", err
	}
	adminTokenInfo, resp := iam.VerifyToken(ctx, token)
	if resp != nil {
		return "", resp.Error()
	}
	b.adminToken = token
	b.adminTokenExpiry = adminTokenInfo.Expiry
	return b.adminToken, nil
}

func (b *ibmCloudAuthBackend) getIAMHelper(ctx context.Context, s logical.Storage) (iamHelper, *logical.Response) {
	b.iamHelperLock.RLock()
	unlockFunc := b.iamHelperLock.RUnlock
	defer func() { unlockFunc() }()

	if b.iamHelper != nil {
		return b.iamHelper, nil
	}
	b.iamHelperLock.RUnlock()

	b.iamHelperLock.Lock()
	unlockFunc = b.iamHelperLock.Unlock

	if b.iamHelper != nil {
		return b.iamHelper, nil
	}

	config, resp := b.getConfig(ctx, s)
	if resp != nil {
		return nil, resp
	}
	b.iamHelper = new(ibmCloudHelper)
	b.iamHelper.Init(config.IAMEndpoint, config.UserManagementEndpoint)

	return b.iamHelper, nil
}

const backendHelp = `
The IBM Cloud backend plugin allows authentication for IBM Public Cloud.
`
