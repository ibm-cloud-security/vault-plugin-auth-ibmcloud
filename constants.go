package ibmcloudauth

const (
	iamEndpointFieldDefault = "https://iam.cloud.ibm.com"
	openIDIssuer            = "https://iam.cloud.ibm.com/identity"
	userMgmtEndpointDefault = "https://user-management.cloud.ibm.com"
)

//Number of minutes to renew the admin token before expiration
const adminTokenRenewBeforeExpirationMinutes = 5

// request & response fields
const (
	accountIDField              = "account_id"
	iamEndpointField            = "iam_endpoint"
	userManagementEndpointField = "user_management_endpoint"
	identifierField             = "identifier"
	roleField                   = "role"
	apiKeyField                 = "api_key"
	tokenKeyField               = "token"
	redacted                    = "<redacted>"
	iamIDField                  = "IAM_ID"
	subjectField                = "subject"
	subjectTypeField            = "sub_type"
	serviceIDSubjectType        = "ServiceId"
	apiKeyID                    = "api_key_id"
)
