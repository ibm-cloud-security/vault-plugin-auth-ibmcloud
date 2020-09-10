package iam_plugin

const (
	iamEndpointFieldDefault    = "https://iam.cloud.ibm.com"
	iamIdentityEndpointDefault = "https://iam.cloud.ibm.com/identity"
)

// IAM API paths
const (
	accessGroupMembershipCheck = "/v2/groups/%s/members/%s"
)

//Number of minutes to renew the admin token before expiration
const adminTokenRenewBeforeExpirationMinutes = 5

// request & response fields
const (
	roleField     = "role"
	apiKeyField   = "api_key"
	tokenKeyField = "token"
	redacted      = "<redacted>"
	iamIDField    = "IAM_ID"
	subjectField  = "subject"
)
