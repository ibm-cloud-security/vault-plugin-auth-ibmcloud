# opensrc-vault-plugin-auth-iam

This plugin allows you to login to Vault using IBM Cloud API keys.
The plugin allow creation of roles which map Vault policies
to IBM Cloud Access Groups and/or a list of IBM Cloud user (subject) IDs.

## Installation 

Build the plugin:
`go build -o iam cmd/iam/main.go`


Copy the executable into Vault's configured plugin folder


Register the plugin:
```
export SHA256=$(shasum -a 256 "iam" | cut -d' ' -f1)
vault plugin register -sha256=${SHA256} auth iam
```


Enable (mount) the plugin: `vault auth enable iam`

## Usage
The general usage pattern is for the administrator to create one or more roles which
map Vault policies to IBM Cloud Access Groups and/or a list of IBM Cloud user (subject) IDs.

Users can then log into Vault using their API key and specify a role name.

A short description of usage and command line parameters follow using the Vault CLI. Full
REST API documentation with sample inputs and outputs is forthcoming.

### Role CLI

The general form is: `vault write auth/iam/role/<role_name>`.
The `vault list`, `vault read`, and `vault delete` commands are implemented for the role path.

Create/update parameters:

* `bound_access_group_ids` - a list string array/list of one or more IBM Cloud Access Groups to bind to the role.
* `bound_subjects` - a list string array/list of one or more IBM Cloud user or service IDs to bind to the role.
For example "myuser@mycompany.com, ServiceId-068bda08-c891-4a7f-82cf-3b2111ae3c43"
* `token_policies` - a list of Vault polices to bind to the role
* `token_*` - all of the common `token_` parameters for roles. For now, see https://github.com/hashicorp/vault/blob/master/sdk/helper/tokenutil/tokenutil.go 

You must specify at lest one bound entity on either `bound_access_group_ids` or `bound_subjects`.

#### Example of a role creation

This command creates a role named `developer`. It associates the Vault policies named `prod` and `dev` with the role.
It further binds the role to an IBM Cloud user ID (myuser@company.com), a service ID, and two IBM Cloud Access Groups.

```
vault write auth/iam/role/developer token_policies="prod,dev" \
     bound_access_group_ids="AccessGroupId-43f12338-fc2c-41cd-b4f9-14eff0cbeb47, AccessGroupId-43f12111-fc2c-41cd-b4f9-14eff0cbeb47" \
     bound_subjects="ServiceId-068bda08-c891-4a7f-82cf-3b2111ae3c43, myuser@mycomany.com"
```

### Login CLI

The auth plugin's login CLI is by default at this path: `auth/iam/login`

There are two required parameters to the login path:
* `api_key` - The IBM Cloud user (or service ID's) API key.
* `role` - The role to use

During a login attempt, the auth plugin will obtain an IBM Cloud IAM token using the provided API key.
For a successful login, the subject of the obtained IAM token must in the specified role's `bound_subjects` list
or the subject must be a member of at least one of the role's bound access groups.

#### Example of login 

Using the `developer` role defined in the example above, a login command looks like this:

```
$ vault write auth/iam/login api_key=theRedactedKey role=developer
Key                  Value
---                  -----
token                s.3vtUw7Mgyr4tbeEHel0Z5vkW
token_accessor       3U8luvBYDJSBLUqMCnzIUChN
token_duration       768h
token_renewable      true
token_policies       ["default" "dev" "prod"]
identity_policies    []
policies             ["default" "dev" "prod"]
token_meta_IAM_ID    iam-ServiceId-8c243dbd-de02-4435-86ce-493a5782afe8
token_meta_role      developer
token_meta_sub       ServiceId-8c243dbd-de02-4435-86ce-493a5782afe8

```