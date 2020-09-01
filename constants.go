package iam_plugin

const (
	iamEndpointFieldDefault    = "https://iam.cloud.ibm.com"
	iamIdentityEndpointDefault = "https://iam.cloud.ibm.com/identity"
)

// IAM API paths
const (
	accessGroupMembershipCheck = "/v2/groups/%s/members/%s"
)

// request & response fields
const (
	roleField   = "role"
	apiKeyField = "api_key"
)
