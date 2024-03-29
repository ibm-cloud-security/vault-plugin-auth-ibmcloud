# IBM Cloud Auth Method

This is a standalone backend plugin for use with [HashiCorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows for various IBM Cloud entities to authenticate with Vault.

User accounts or service IDs can sign in using an IBM Cloud IAM access token or API key.

## Installation

The plugin must be built before it is installed. Follow the steps in [Developing](#Developing) to build
the plugin executable.

Copy the executable into Vault's configured plugin folder:
`cp bin/vault-plugin-auth-ibmcloud $VAULT_INSTALL/plugins`

Register the plugin:
```
export SHA256=$(shasum -a 256 "bin/vault-plugin-auth-ibmcloud" | cut -d' ' -f1)
vault plugin register -sha256=${SHA256} auth vault-plugin-auth-ibmcloud
```

Enable (mount) the plugin: `vault auth enable -plugin-name="vault-plugin-auth-ibmcloud" -path="ibmcloud" plugin`

## Usage
The general usage pattern is for the administrator to create one or more roles which
map Vault policies to IBM Cloud Access Groups and/or a list of IBM Cloud user (subject) IDs.

Users or service IDs can then log into Vault using by specifying a role name and either their an IBM Cloud IAM access token or API key.

The auth method must be configured in advance before authentication.

# API documentation
This documentation assumes the plugin method is mounted at the `/auth/ibmcloud` path in Vault. Since it is possible to
enable auth methods at any location, please update your API calls accordingly.


## Configure

Configures the credentials and parameters required for the plugin to perform API calls to IBM Cloud IAM and User Management. These
credentials will be used to verify user account and service ID account access and access group membership. The user account or
service ID providing the API key needs to have the following permissions:

* `Viewer` on `Access Groups Service`
* `Viewer` on `IAM Identity Service`
* `Operator` on `IAM Identity Service` if root credential rotation will be used
* `Viewer` on `User Management Service` 

Configures the auth method and must be done before authentication can succeed.

| Method   | Path |
|----------|-------------------------------------------------|
| `POST`   |  `/auth/ibmcloud/config`                             |


### Parameters
* `api_key (string: <required>)` - An API key for a service ID or user with sufficient permissions to verify IBM Cloud access group
membership for the all the access groups bound to the plugin's roles.
* `account_id (string: <required>)` - An IBM Cloud account ID. The auth method will only authenticate users or service IDs that
have access to this account.
* `iam_endpoint (string: <optional>)` - The custom or private IAM endpoint. For example `https://private.iam.cloud.ibm.com`.
If unspecified the public endpoint, `https://iam.cloud.ibm.com`, is used.
* `user_management_endpoint (string: <optional>)` - The custom or private user management endpoint. For example `https://private.user-management.cloud.ibm.com`.
If unspecified the public endpoint, `https://user-management.cloud.ibm.com`, is used.

### Sample Payload

```json
{
  "api_key":    "Yl5OBiNlgpx...",
  "account_id": "abd85726cbd..."
}
```

### Sample Request
```shell script
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://127.0.0.1:8200/v1/auth/ibmcloud/config
```

## Read Config
Returns the configuration, if any. Credentials are redacted in the output.

| Method   | Path |
|----------|--------------------------------------------------|
| `GET`    |  `/auth/ibmcloud/config`                              |


### Sample Request
```shell script
$ curl \
    --header "X-Vault-Token: ..." \
    https://127.0.0.1:8200/v1/auth/ibmcloud/config
```

### Sample Response
```json
{
  "data": {
    "api_key": "<redacted>",
    "account_id": "abd85726cbd...",
    "iam_endpoint": "https://iam.cloud.ibm.com",
    "user_management_endpoint": "https://user-management.cloud.ibm.com",
  },
  "...": "..."

}
```

## Rotate Root Credentials

Rotates the IBM Cloud API key used by Vault for this mount. A new key will be generated
for same user or service ID and account as the existing API key. The configuration is updated
and then the old API key is deleted.

The ID of the new API key is returned in the response.


| Method   | Path |
|----------|-------------------------------------------------|
| `POST`   |  `/auth/ibmcloud/config/rotate-root`            |


### Sample Request
```shell script
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    https://127.0.0.1:8200/v1/auth/ibmcloud/config/rotate-root
```

### Sample Response
```json
{
  "data": {
    "api_key_id": "ApiKey-0abbbbbb-21cc-4dcc-a9cc-b59bc15c7aa1"
  },
  "...": "..."
}
```

## Delete Config
Deletes the previously configured configuration and clears the credentials in the plugin.

| Method     | Path |
|----------- |--------------------------------------------------|
| `DELETE`   |  `/auth/ibmcloud/config`                              |

### Sample Request
```shell script
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    https://127.0.0.1:8200/v1/auth/ibmcloud/config
```

## Create Role
Registers a role in the method. Role types have specific entities that can perform login operations against
this endpoint. Constraints specific to the role type must be set on the role. These are applied to the
authenticated entities attempting to login.

| Method     | Path                                             |
|----------- |--------------------------------------------------|
| `POST`     |  `/auth/ibmcloud/role/:name`                          |


### Parameters

* `name (string: <required>)` - Name of the role.

One or more the following must be specified:
* `bound_subjects (array: [])` - The list of subject ids that login is restricted to.
* `bound_access_group_ids (array: [])` - `The list of IBM Cloud IAM access group ids that login is restricted to.

Standard token parameters:
* `token_policies (array: [] or comma-delimited string: "")` - List of policies to encode onto generated tokens.
* `token_ttl (integer: 0 or string: "") `- The incremental lifetime for generated tokens. This current value of this will be referenced at renewal time.
* `token_max_ttl (integer: 0 or string: "")` - The maximum lifetime for generated tokens. This current value of this will be referenced at renewal time.
* `token_bound_cidrs (array: [] or comma-delimited string: "")` - List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully, and ties the resulting token to these blocks as well.
* `token_explicit_max_ttl (integer: 0 or string: "")` - If set, will encode an explicit max TTL onto the token. This is a hard cap even if token_ttl and token_max_ttl would otherwise allow a renewal.
* `token_no_default_policy (bool: false)` - If set, the default policy will not be set on generated tokens; otherwise it will be added to the policies set in token_policies.
* `token_num_uses (integer: 0)` - The maximum number of times a generated token may be used (within its lifetime); 0 means unlimited. If you require the token to have the ability to create child tokens, you will need to set this value to 0.
* `token_period (integer: 0 or string: "")` - The period, if any, to set on the token.
* `token_type (string: "")` - The type of token that should be generated. Can be service, batch, or default to use the mount's tuned default (which unless changed will be service tokens). For token store roles, there are two additional possibilities: default-service and default-batch which specify the type to return unless the client requests a different type at generation time.

### Sample Payload
```json
{
  "token_policies": ["dev", "prod"],
  "bound_access_group_ids": ["AccessGroupId-43f12338-fc2c-41cd-b4f9-14eff0cbeb47", "AccessGroupId-43f12111-fc2c-41cd-b4f9-14eff0cbeb21"],
  "bound_subjects": ["ServiceId-068bda08-c891-4a7f-82cf-3b2111ae3c43", "myuser@mycomany.com"]
}
```

### Sample Request
```shell script
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://127.0.0.1:8200/v1/auth/ibmcloud/role/dev-role
```
## Read Role
Returns the previously registered role configuration.

| Method     | Path                                             |
|----------- |--------------------------------------------------|
| `GET`      |  `/auth/ibmcloud/role/:name`                          |
 
### Parameters

* `name (string: <required>)` - Name of the role.


### Sample Request
```shell script
$ curl \
    --header "X-Vault-Token: ..." \
    https://127.0.0.1:8200/v1/auth/ibmcloud/role/dev-role
```

### Sample Response
```json
{
  "data": {
    "bound_access_group_ids": [
      "AccessGroupId-43f12338-fc2c-41cd-b4f9-14eff0cbeb47",
      "AccessGroupId-43f12111-fc2c-41cd-b4f9-14eff0cbeb21"
    ],
    "bound_subjects": [
      "ServiceId-068bda08-c891-4a7f-82cf-3b2111ae3c43",
      "myuser@mycomany.com"
    ],
    "token_policies": [
      "prod",
      "dev"
    ],
    "token_bound_cidrs": [],
    "token_explicit_max_ttl": 0,
    "token_max_ttl": 0,
    "token_no_default_policy": false,
    "token_num_uses": 0,
    "token_period": 0,
    "token_ttl": 0,
    "token_type": "default"
  },
  "...": "..."

}
```

## List Roles
Lists all the roles that are registered with the plugin.

| Method     | Path                                             |
|----------- |--------------------------------------------------|
| `LIST`     |  `/auth/ibmcloud/role`                                |
 
### Sample Request
 ```shell script
curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    https://127.0.0.1:8200/v1/auth/ibmcloud/role
```

### Sample Response

```json
{
  "data": {
    "keys": ["dev-role", "prod-role"]
  },
  "...": "..."

}
```

## Delete Role
Deletes the previously registered role.

| Method     | Path                                             |
|----------- |--------------------------------------------------|
| `DELETE`   |  `/auth/ibmcloud/role/:name`                          |
 
### Parameters
* `name (string: <required>)` - Name of the role.

### Sample Request
```shell script
 curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    https://127.0.0.1:8200/v1/auth/ibmcloud/role/dev-role
```

## Login

Fetch a token. This endpoint takes a role name and either an IBM Cloud IAM API key or access token.
If an API key is provided, it is used to fetch an access token from IBM Cloud IAM. The access token, either
provided or fetched, is then verified to authenticate the entity. The entity is then checked against the bound
entities of the given role.

| Method     | Path                                             |
|----------- |--------------------------------------------------|
| `POST`     |  `/auth/ibmcloud/login`                               |

### Parameters
* `role (string: <required>)` - Name of the role against which the login is being attempted.

One of the following is required:
* `token (string: "")` - An IBM Cloud IAM access token.
* `api_key (string: "")` - An IBM Cloud IAM API key.

### Sample Payload

Token form:
```json
{
  "role": "dev-role",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

API key form:
```json
{
  "role": "dev-role",
  "api_key": "Yl5OBiNlgpx..."
}
```

### Sample Request
```shell script
$ curl \
    --request POST \
    --data @payload.json \
    https://127.0.0.1:8200/v1/auth/ibmcloud/login
```

### Sample Response
```json
{
  "auth": {
    "client_token": "s.SaizjrPeDs5rVvsmsTQPVmpW",
    "accessor": "Gibi4QfcsFLufAMN8havO9LH",
    "policies": [
      "default",
      "dev",
      "prod"
    ],
    "token_policies": [
      "default",
      "dev",
      "prod"
    ],
    "metadata": {
      "IAM_ID": "iam-ServiceId-068bda08-c891-4a7f-82cf-3b2111ae3c43",
      "role": "dev-role",
      "subject": "ServiceId-068bda08-c891-4a7f-82cf-3b2111ae3c43"
    },
    "lease_duration": 2764800,
    "renewable": true,
    "entity_id": "",
    "token_type": "service",
    "orphan": true
  },
  "...": "..."
}
```

## Developing

For local dev first make sure Go is properly installed, including
setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH). The version
of Go that is installed should match the level required by the version of Vault
that will be used. See [Vault's requirements](https://github.com/hashicorp/vault#developing-vault)
for more information.


Next, clone this repository:

```sh
$ git clone https://github.com/ibm-cloud-security/vault-plugin-auth-ibmcloud
$ cd vault-plugin-auth-ibmcloud
```

You can then download any required build tools by bootstrapping your
environment:

```sh
$ make bootstrap
```

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make
$ make dev
```

For local development, use Vault's "dev" mode for fast setup:

```sh
$ vault server -dev -config vault.hcl
```

Where vault.hcl configures the plugin directory like this:
```
plugin_directory = "./plugins"
```

Follow the setup instructions to copy, register, and enable the plugin.