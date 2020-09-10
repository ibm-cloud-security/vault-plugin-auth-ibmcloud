package iam_plugin

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *icAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			apiKeyField: &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The administrator API key.",
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
	APIKey string `json:"api_key"`
}

func (b *icAuthBackend) config(ctx context.Context, s logical.Storage) (*ibmCloudConfig, error) {
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

func (b *icAuthBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *icAuthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

func (b *icAuthBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
			apiKeyField: displayKey,
		},
	}
	return resp, nil
}

func (b *icAuthBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")

	if err == nil {
		b.reset()
	}

	return nil, err
}

const confHelpSyn = `Configures credentials used to query the IBM Cloud IAM API to verify authenticating accounts`
const confHelpDesc = `
The IBM Cloud auth plugin makes queries to the IBM Cloud IAM API to verify an account
attempting login. The credentials should have sufficient permissions to check
access group membership for all access groups specified in the auth plugin's roles.`
