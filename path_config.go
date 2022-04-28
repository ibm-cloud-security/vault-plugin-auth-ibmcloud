package ibmcloudauth

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *ibmCloudAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			apiKeyField: {
				Type:        framework.TypeString,
				Description: "The administrator API key.",
			},
			accountIDField: {
				Type:        framework.TypeString,
				Description: "The account ID.",
			},
			iamEndpointField: {
				Type:        framework.TypeString,
				Description: "The custom or private IAM endpoint.",
			},
			userManagementEndpointField: {
				Type:        framework.TypeString,
				Description: "The custom or private User Management endpoint.",
			},
		},
		ExistenceCheck: b.pathConfigExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

type ibmCloudConfig struct {
	APIKey                 string `json:"api_key"`
	Account                string `json:"account"`
	IAMEndpoint            string `json:"iam_endpoint"`
	UserManagementEndpoint string `json:"user_management_endpoint"`
}

func (b *ibmCloudAuthBackend) config(ctx context.Context, s logical.Storage) (*ibmCloudConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := new(ibmCloudConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *ibmCloudAuthBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *ibmCloudAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(ibmCloudConfig)
	}

	apiKey, ok := data.GetOk(apiKeyField)
	if ok {
		config.APIKey = apiKey.(string)
	} else {
		return logical.ErrorResponse("the required field %s is missing", apiKeyField), nil
	}

	accountID, ok := data.GetOk(accountIDField)
	if ok {
		config.Account = accountID.(string)
	} else {
		return logical.ErrorResponse("the required field %s is missing", accountIDField), nil
	}

	iamEndpoint, ok := data.GetOk(iamEndpointField)
	if ok {
		config.IAMEndpoint = iamEndpoint.(string)
	} else {
		config.IAMEndpoint = iamEndpointFieldDefault
	}

	userMgmtEndpoint, ok := data.GetOk(userManagementEndpointField)
	if ok {
		config.UserManagementEndpoint = userMgmtEndpoint.(string)
	} else {
		config.UserManagementEndpoint = userMgmtEndpointDefault
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Reset backend
	b.reset()

	return nil, nil
}

func (b *ibmCloudAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	displayKey := config.APIKey
	if displayKey != "" {
		displayKey = redacted
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			apiKeyField:                 displayKey,
			accountIDField:              config.Account,
			iamEndpointField:            config.IAMEndpoint,
			userManagementEndpointField: config.UserManagementEndpoint,
		},
	}
	return resp, nil
}

func (b *ibmCloudAuthBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")

	if err == nil {
		b.reset()
	}

	return nil, err
}

func (b *ibmCloudAuthBackend) verifyPluginIsConfigured(ctx context.Context, req *logical.Request) error {
	// verify the plugin is configured
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("failed to load configuration", "error", err)
		return errors.New("no configuration was found")
	}
	if config == nil || config.APIKey == "" {
		return errors.New("no API key was set in the configuration")
	}
	if config.Account == "" {
		return errors.New("no account ID was set in the configuration")
	}

	return nil
}

func (b *ibmCloudAuthBackend) getConfig(ctx context.Context, s logical.Storage) (*ibmCloudConfig, *logical.Response) {
	// verify the plugin is configured
	config, err := b.config(ctx, s)
	if err != nil {
		b.Logger().Error("failed to load configuration", "error", err)
		return nil, logical.ErrorResponse("no configuration was found")
	}
	if config == nil || config.APIKey == "" {
		return nil, logical.ErrorResponse("no API key was set in the configuration")
	}
	if config.Account == "" {
		return nil, logical.ErrorResponse("no account ID was set in the configuration")
	}

	return config, nil
}

const confHelpSyn = `Configures credentials and account used to query the IBM Cloud IAM API to verify authenticating accounts`
const confHelpDesc = `
The IBM Cloud auth plugin makes queries to the IBM Cloud IAM API to verify an account
attempting login. The configuration requires an API key and an account ID. The API key
specified should have sufficient permissions to check
access group membership for all access groups specified in the auth plugin's roles.
The account ID is used to scope the users allowed to authenticate to Vault. The users
must have access to the configured account.`
