package iam_plugin

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
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
				Type: framework.TypeString,
				Description: `
An IBM Cloud IAM API key that IBM Cloud auth plugin will use to authenticate and authorize the user against IBM Cloud IAM.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: apiKeyField,
				},
				Required: true,
			},
			roleField: {
				Type: framework.TypeString,
				Description: `
Name of the role against which the login is being attempted.`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: roleField,
				},
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
	roleName := data.Get(roleField).(string)
	if roleName == "" {
		return logical.ErrorResponse(fmt.Sprintf("role name is required: %s", roleField)), nil
	}
	apiKey := data.Get(apiKeyField).(string)
	if apiKey == "" {
		return logical.ErrorResponse(fmt.Sprintf("API key is required: %s", apiKeyField)), nil
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
	info, resp, err := b.verifyAuth(ctx, apiKey, role)
	if resp != nil || err != nil {
		return resp, err
	}

	auth := &logical.Auth{
		Metadata: map[string]string{
			"IAM_ID": info.id,
			"sub":    info.sub,
			"role":   roleName,
		},
		InternalData: map[string]interface{}{
			"apiKey": apiKey,
			"role":   roleName,
		},
	}

	role.PopulateTokenAuth(auth)

	// Compose the response
	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *icAuthBackend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role"].(string)
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
	apiKeyRaw, ok := req.Auth.InternalData["apiKey"]
	if !ok {
		return nil, fmt.Errorf("an error occured retrieving the API key")
	}
	apiKey := apiKeyRaw.(string)

	if _, resp, err := b.verifyAuth(ctx, apiKey, role); resp != nil || err != nil {
		return resp, err
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
	return resp, nil
}

/*
	Authenticates the user and does verification of their IBM Cloud token and verifies them against the role's bound
	entities.
	The logical.Response and error returns are both returns that should be checked and no further processing performed
	if either are null.
*/
func (b *icAuthBackend) verifyAuth(ctx context.Context, apiKey string, role *ibmCloudRole) (*tokenInfo, *logical.Response, error) {
	// obtain the token
	accessToken, err := obtainToken(b.httpClient, iamIdentityEndpointDefault, apiKey)
	if err != nil {
		b.Logger().Debug("obtain user token failed", "error", err)
		return nil, nil, logical.ErrPermissionDenied
	}
	// verify the token
	provider, err := b.getProvider()
	if err != nil {
		return nil, nil, errwrap.Wrapf("error getting provider for login operation: {{err}}", err)
	}

	oidcConfig := &oidc.Config{
		SkipClientIDCheck: true,
	}
	verifier := provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, accessToken)
	if err != nil {
		return nil, logical.ErrorResponse(errwrap.Wrapf("error validating token: {{err}}", err).Error()), nil
	}

	// Get the IAM access token claims we are interested in
	iamAccessTokenClaims := iamAccessTokenClaims{}
	if err := idToken.Claims(&iamAccessTokenClaims); err != nil {
		return nil, nil, errwrap.Wrapf("unable to successfully parse all claims from token: {{err}}", err)
	}

	// Check for the subject in the bound subject list
	if !strutil.StrListContains(role.BoundSubscriptionsIDs, idToken.Subject) {
		// Check the access groups next
		subjectFoundInGroup := false
		for _, group := range role.BoundAccessGroupIDs {
			if err = checkGroupMembership(b.httpClient, group, iamAccessTokenClaims.IAMID, accessToken); err == nil {
				subjectFoundInGroup = true
				break
			}
		}
		if !subjectFoundInGroup {
			b.Logger().Debug("The subject was not found in the subject list or access groups for this role.", "error", err)
			return nil, nil, logical.ErrPermissionDenied
		}
	}

	tokenInfo := &tokenInfo{
		id:  iamAccessTokenClaims.IAMID,
		sub: idToken.Subject,
	}

	return tokenInfo, nil, nil
}

//TODO (smatzek): Fill in login path help
const loginHelpSyn = `Authenticate and authorize a user request to access IBM Cloud secrets using IBM Cloud IAM.`
const loginHelpDesc = ``
