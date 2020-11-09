package ibmcloudauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

// pathsRole returns the path configurations for the CRUD operations on roles
func pathsRole(b *ibmCloudAuthBackend) []*framework.Path {
	p := []*framework.Path{
		{
			Pattern: "role/?",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
				},
			},
			HelpSynopsis:    strings.TrimSpace(roleHelp["role-list"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role-list"][1]),
		},
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"bound_subjects": {
					Type:        framework.TypeCommaStringSlice,
					Description: `Comma-separated list of subscription ids that login is restricted to.`,
				},
				"bound_access_group_ids": {
					Type:        framework.TypeCommaStringSlice,
					Description: `Comma-separated list of IAM Access Group ids that login is restricted to.`,
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},

			HelpSynopsis:    strings.TrimSpace(roleHelp["role"][0]),
			HelpDescription: strings.TrimSpace(roleHelp["role"][1]),
		},
	}

	tokenutil.AddTokenFields(p[1].Fields)

	return p
}

type ibmCloudRole struct {
	tokenutil.TokenParams

	// Role binding properties
	BoundSubscriptionsIDs []string `json:"bound_subjects"`
	BoundAccessGroupIDs   []string `json:"bound_access_group_ids"`
}

// role takes a storage backend and the name and returns the role's storage
// entry
func (b *ibmCloudAuthBackend) role(ctx context.Context, s logical.Storage, name string) (*ibmCloudRole, error) {
	raw, err := s.Get(ctx, "role/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := new(ibmCloudRole)
	if err := json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}

	return role, nil
}

// pathRoleExistenceCheck returns whether the role with the given name exists or not.
func (b *ibmCloudAuthBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

// pathRoleList is used to list all the Roles registered with the backend.
func (b *ibmCloudAuthBackend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

// pathRoleRead grabs a read lock and reads the options set on the role from the storage
func (b *ibmCloudAuthBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	d := map[string]interface{}{
		"bound_subjects":         role.BoundSubscriptionsIDs,
		"bound_access_group_ids": role.BoundAccessGroupIDs,
	}

	role.PopulateTokenData(d)

	return &logical.Response{
		Data: d,
	}, nil
}

// pathRoleDelete removes the role from storage
func (b *ibmCloudAuthBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name required"), nil
	}

	// Delete the role itself
	if err := req.Storage.Delete(ctx, "role/"+strings.ToLower(roleName)); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRoleCreateUpdate registers a new role with the backend or updates the options
// of an existing role
func (b *ibmCloudAuthBackend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	// Check if the role already exists
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	// Create a new entry object if this is a CreateOperation
	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("role entry not found during update operation")
		}
		role = new(ibmCloudRole)
	}

	if err := role.ParseTokenFields(req, data); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if role.TokenPeriod > b.System().MaxLeaseTTL() {
		return logical.ErrorResponse("token period of %q is greater than the backend's maximum lease TTL of %q", role.TokenPeriod.String(), b.System().MaxLeaseTTL().String()), nil
	}

	if role.TokenNumUses < 0 {
		return logical.ErrorResponse("token num uses cannot be negative"), nil
	}

	if boundAccessGroupIDs, ok := data.GetOk("bound_access_group_ids"); ok {
		role.BoundAccessGroupIDs = boundAccessGroupIDs.([]string)
	}

	if boundSubscriptionsIDs, ok := data.GetOk("bound_subjects"); ok {
		role.BoundSubscriptionsIDs = boundSubscriptionsIDs.([]string)
	}

	if len(role.BoundSubscriptionsIDs) == 0 &&
		len(role.BoundAccessGroupIDs) == 0 {
		return logical.ErrorResponse("must have at least one bound constraint when creating/updating a role"), nil
	}

	// Check that the TTL value provided is less than the MaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if role.TokenMaxTTL > 0 && role.TokenTTL > role.TokenMaxTTL {
		return logical.ErrorResponse("ttl should not be greater than max_ttl"), nil
	}

	var resp *logical.Response
	if role.TokenMaxTTL > b.System().MaxLeaseTTL() {
		resp = &logical.Response{}
		resp.AddWarning("max_ttl is greater than the system or backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	// Store the entry.
	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(roleName), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for role %s", roleName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return resp, nil
}

var roleHelp = map[string][2]string{
	"role-list": {
		"Lists all the roles registered with the backend.",
		"The list will contain the names of the roles.",
	},
	"role": {
		"Register an role with the backend.",
		`A role is required to authenticate with this backend. A role binds Vault policies and has
required attributes that an authenticating entity must fulfill to login against this role.
After authenticating the instance, Vault uses the bound policies to determine which resources
the authorization token for the instance can access.

The bindings, token polices and token settings can all be configured using this endpoint`,
	},
}
