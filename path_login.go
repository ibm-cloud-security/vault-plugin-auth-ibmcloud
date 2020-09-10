package iam_plugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathLogin(b *icAuthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			apiKeyField: {
				Type:        framework.TypeString,
				Description: `An IBM Cloud IAM API key.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: apiKeyField,
				},
			},
			tokenKeyField: {
				Type:        framework.TypeString,
				Description: `An IBM Cloud access token.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: tokenKeyField,
				},
			},
			roleField: {
				Type:        framework.TypeString,
				Description: `Name of the role against which the login is being attempted. Required.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: roleField,
				},
				Required: true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathAuthLogin,
			},
		},
		HelpSynopsis:    loginHelpSyn,
		HelpDescription: loginHelpDesc,
	}
}

func (b *icAuthBackend) pathAuthLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName, ok := data.Get(roleField).(string)
	if !ok || roleName == "" {
		return logical.ErrorResponse(fmt.Sprintf("role name is required: %s", roleField)), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid role name %q", roleName)), nil
	}

	if len(role.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	apiKey := data.Get(apiKeyField).(string)
	callerToken := data.Get(tokenKeyField).(string)

	if apiKey != "" {
		callerToken, err = obtainToken(b.httpClient, iamIdentityEndpointDefault, apiKey)
		if err != nil {
			b.Logger().Debug("obtain user token failed", "error", err)
			return nil, logical.ErrPermissionDenied
		}
	} else if callerToken != "" {
		config, err := b.config(ctx, req.Storage)
		if err != nil {
			b.Logger().Error("failed to load configuration", "error", err)
			return nil, errors.New("no configuration was found. Token login requires the auth plugin to be configured with an API key")
		}
		if config == nil || config.APIKey == "" {
			return nil, errors.New("no API key was set in the configuration. Token login requires the auth plugin to be configured with an API key")
		}
	} else {
		return logical.ErrorResponse(fmt.Sprintf("Either %s or %s must specified.", apiKeyField, tokenKeyField)), nil
	}
	callerTokenInfo, resp := b.verifyToken(ctx, callerToken)
	if resp != nil {
		return resp, nil
	}

	err = b.verifyBoundEntities(callerToken, callerTokenInfo.Subject, callerTokenInfo.IAMid, role)
	if err != nil {
		return nil, err
	}

	auth := &logical.Auth{
		Metadata: map[string]string{
			iamIDField:   callerTokenInfo.IAMid,
			subjectField: callerTokenInfo.Subject,
			roleField:    roleName,
		},
	}
	if apiKey != "" {
		auth.InternalData = map[string]interface{}{
			apiKeyField: apiKey,
		}
	}
	role.PopulateTokenAuth(auth)

	// Compose the response
	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *icAuthBackend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName, ok := req.Auth.Metadata[roleField]
	if roleName == "" {
		return logical.ErrorResponse("role name metadata not associated with auth token, invalid"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	} else if role == nil {
		return logical.ErrorResponse("role '%s' no longer exists", roleName), nil
	} else if !policyutil.EquivalentPolicies(role.TokenPolicies, req.Auth.TokenPolicies) {
		return logical.ErrorResponse("policies on role '%s' have changed, cannot renew", roleName), nil
	}

	iamID := req.Auth.Metadata[iamIDField]
	subject := req.Auth.Metadata[subjectField]
	var accessCheckToken string

	apiKeyRaw, ok := req.Auth.InternalData["apiKey"]
	if ok {
		apiKey := apiKeyRaw.(string)
		userToken, err := obtainToken(b.httpClient, iamIdentityEndpointDefault, apiKey)
		if err != nil {
			b.Logger().Debug("obtain user token failed", "error", err)
			return logical.ErrorResponse("error reauthorizing with the token's stored API key, cannot renew"), nil
		}
		_, resp := b.verifyToken(ctx, userToken)
		if resp != nil {
			return resp, nil
		}
		accessCheckToken = userToken
	} else {
		accessCheckToken, err = b.getAdminToken(ctx, req.Storage)
		if err != nil {
			b.Logger().Error("error obtaining the token for the configured API key", "error", err)
			return nil, err
		}
	}
	err = b.verifyBoundEntities(accessCheckToken, subject, iamID, role)
	if err != nil {
		return nil, err
	}
	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
	return resp, nil
}

func (b *icAuthBackend) verifyBoundEntities(accessToken, subject, iamID string, role *ibmCloudRole) error {
	// Check for the subject in the bound subject list
	if !strutil.StrListContains(role.BoundSubscriptionsIDs, subject) {
		var err error
		// Check the access groups next
		subjectFoundInGroup := false
		for _, group := range role.BoundAccessGroupIDs {
			if err = checkGroupMembership(b.httpClient, group, iamID, accessToken); err == nil {
				subjectFoundInGroup = true
				break
			}
		}
		if !subjectFoundInGroup {
			b.Logger().Debug("The subject was not found in the subject list or access groups for this role.", "error", err)
			return logical.ErrPermissionDenied
		}
	}
	return nil
}

const loginHelpSyn = `Authenticates IBM Cloud entities with Vault.`
const loginHelpDesc = `
Authenticate IBM Cloud entities.

Currently supports authentication for:

User accounts or service IDs
=====================
User accounts or service IDs can sign in using an IAM access token or API key.
If an IAM access token is used, the plugin must be configured with an API key that has authority to check access group
membership. See the configuration help for more information.

Vault verifies the access token if one is provided and parses the identity of the account.

If an API key is provided, Vault will log into IBM Cloud and create an IAM access token for the account.

Renewal is rejected if the role has changed or no longer exists, or if the identity is no longer in the role's subject
list or access groups.
`
