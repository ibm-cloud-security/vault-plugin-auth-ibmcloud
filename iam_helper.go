package ibmcloudauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/logical"
)

// IAM API paths
const (
	accessGroupMembershipCheck = "/v2/groups/%s/members/%s"
	serviceIDDetails           = "/v1/serviceids/%s"
	getUserProfile             = "/v2/accounts/%s/users/%s"
	identityToken              = "/identity/token"
	identity                   = "/identity"
	v1APIKeys                  = "/v1/apikeys"
	v1APIKeysID                = v1APIKeys + "/%s"
	v1APIKeyDetails            = "/v1/apikeys/details"
)

// A struct to contain information from IBM Cloud tokens that we want to include in Vault token metadata
type tokenInfo struct {
	IAMid       string
	Identifier  string
	Subject     string
	SubjectType string
	Expiry      time.Time
}

type iamAccessTokenClaims struct {
	IAMID       string `json:"iam_id"`
	SubjectType string `json:"sub_type"`
	Identifier  string `json:"identifier"`
	// Other access token claims that we do not currently use
	//ID         string `json:"id"`
	//RealmID    string `json:"realmid"`
	//GivenName  string `json:"given_name"`
	//FamilyName string `json:"family_name"`
	//Name       string `json:"name"`
	//Email      string `json:"email"`
	//Account    Account  `json:"account"`
	//GrantType string   `json:"grant_type"`
	//Scope     string   `json:"scope"`
	//ClientID  string   `json:"client_id"`
	//ACR       int      `json:"acr"`
	//AMR       []string `json:"amr"`
}

type serviceIDDetail struct {
	Account string `json:"account_id"`
}

type APIKeyV1Response struct {
	APIKey string `json:"apikey"`
	ID     string `json:"id"`
}

type APIKeyDetailsResponse struct {
	ID        string `json:"id"`
	IAMID     string `json:"iam_id"`
	AccountID string `json:"account_id"`
}

type iamHelper interface {
	ObtainToken(apiKey string) (string, error)
	VerifyToken(ctx context.Context, token string) (*tokenInfo, *logical.Response)
	CheckServiceIDAccount(iamToken, identifier, accountID string) error
	CheckUserIDAccount(iamToken, iamID, accountID string) error
	CheckGroupMembership(groupID, iamID, iamToken string) error
	CreateAPIKey(iamToken, IAMid, accountID, name, description string) (*APIKeyV1Response, error)
	DeleteAPIKey(iamToken, apiKeyID string) error
	GetAPIKeyDetails(iamToken, apiKeyValue string) (*APIKeyDetailsResponse, error)
	Init(iamEndpoint, userManagementEndpoint string)
	Cleanup()
}

type ibmCloudHelper struct {
	providerLock           sync.RWMutex
	provider               *oidc.Provider
	providerCtx            context.Context
	providerCtxCancel      context.CancelFunc
	httpClient             *http.Client
	iamEndpoint            string
	userManagementEndpoint string
}

func (h *ibmCloudHelper) Init(iamEndpoint, userManagementEndpoint string) {
	h.providerCtx, h.providerCtxCancel = context.WithCancel(context.Background())
	h.httpClient = cleanhttp.DefaultPooledClient()
	h.iamEndpoint = iamEndpoint
	h.userManagementEndpoint = userManagementEndpoint
}

func (h *ibmCloudHelper) Cleanup() {
	h.providerLock.Lock()
	if h.providerCtxCancel != nil {
		h.providerCtxCancel()
	}
	h.providerLock.Unlock()
}

func (h *ibmCloudHelper) getProvider() (*oidc.Provider, error) {
	h.providerLock.RLock()
	unlockFunc := h.providerLock.RUnlock
	defer func() { unlockFunc() }()

	if h.provider != nil {
		return h.provider, nil
	}

	h.providerLock.RUnlock()
	h.providerLock.Lock()
	unlockFunc = h.providerLock.Unlock

	if h.provider != nil {
		return h.provider, nil
	}

	identityURL := h.getIAMURL(identity)
	providerCtx := h.providerCtx

	// Use the InsecureIssuerURLContext if the idenity URL does not equal the issuer
	// URL. This is the case with IBM Cloud private endpoints.
	if identityURL != openIDIssuer {
		providerCtx = oidc.InsecureIssuerURLContext(h.providerCtx, openIDIssuer)
	}

	provider, err := oidc.NewProvider(providerCtx, identityURL)
	if err != nil {
		return nil, errwrap.Wrapf("error creating provider with given values: {{err}}", err)
	}

	h.provider = provider
	return provider, nil
}

func (h *ibmCloudHelper) CheckGroupMembership(groupID, iamID, iamToken string) error {
	r, err := http.NewRequest(http.MethodHead, h.getIAMURL(accessGroupMembershipCheck, groupID, iamID), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request for creating policy: {{err}}", err)
	}

	r.Header.Set("Authorization", iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")

	_, err = httpRequestCheckStatus(h.httpClient, r, http.StatusNoContent)
	return err
}

/**
Obtain an IAM token by way of an API Key
*/
func (h *ibmCloudHelper) ObtainToken(apiKey string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Set("apikey", apiKey)
	data.Set("response_type", "cloud_iam")

	req, err := http.NewRequest(http.MethodPost, h.getIAMURL(identityToken), strings.NewReader(data.Encode()))
	if err != nil {
		return "", errwrap.Wrapf("Error creating obtain token request: {{err}}", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", errwrap.Wrapf("Error obtaining token: {{err}}", err)
	}
	defer closeResponse(resp)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", errwrap.Wrapf("Error decoding the obtained token: {{err}}", err)
	} else if _, ok := result["errorMessage"]; ok {
		return "", fmt.Errorf("error message obtaining token: %s", result["errorMessage"])
	}
	return result["access_token"].(string), nil
}

/**
Verifies an IBM Cloud IAM token. If successful, it will return a tokenInfo
with relevant items contained in the token.
*/
func (h *ibmCloudHelper) VerifyToken(ctx context.Context, token string) (*tokenInfo, *logical.Response) {
	// verify the token
	provider, err := h.getProvider()
	if err != nil {
		return nil, logical.ErrorResponse("an error occurred retreiving the OIDC provider: %s", err)
	}

	oidcConfig := &oidc.Config{
		SkipClientIDCheck: true,
	}
	verifier := provider.Verifier(oidcConfig)
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, logical.ErrorResponse("an error occurred verifying the token %s", err)
	}

	// Get the IAM access token claims we are interested in
	iamAccessTokenClaims := iamAccessTokenClaims{}
	if err := idToken.Claims(&iamAccessTokenClaims); err != nil {
		return nil, logical.ErrorResponse("unable to successfully parse all claims from token: %s", err)
	}

	return &tokenInfo{
		IAMid:       iamAccessTokenClaims.IAMID,
		Identifier:  iamAccessTokenClaims.Identifier,
		SubjectType: iamAccessTokenClaims.SubjectType,
		Subject:     idToken.Subject,
		Expiry:      idToken.Expiry,
	}, nil

}

func (h *ibmCloudHelper) CheckServiceIDAccount(iamToken, identifier, accountID string) error {
	r, err := http.NewRequest(http.MethodGet, h.getIAMURL(serviceIDDetails, identifier), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request for creating policy: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return err
	}

	if httpStatus != 200 {
		return fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	idInfo := new(serviceIDDetail)

	if err := json.Unmarshal(body, &idInfo); err != nil {
		return err
	}

	if accountID != idInfo.Account {
		return fmt.Errorf("service ID account %s does not match the configured account %s", idInfo.Account, accountID)
	}

	return nil
}

func (h *ibmCloudHelper) CheckUserIDAccount(iamToken, iamID, accountID string) error {
	r, err := http.NewRequest(http.MethodGet, h.getUserManagementURL(getUserProfile, accountID, iamID), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request for creating policy: {{err}}", err)
	}

	r.Header.Set("Authorization", iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	_, err = httpRequestCheckStatus(h.httpClient, r, http.StatusOK)
	return err
}

func (h *ibmCloudHelper) CreateAPIKey(iamToken, IAMid, accountID, name, description string) (*APIKeyV1Response, error) {
	requestBody, err := json.Marshal(map[string]interface{}{
		"name":        name,
		"iam_id":      IAMid,
		"account_id":  accountID,
		"description": description,
		"store_value": false,
	})
	if err != nil {
		return nil, errwrap.Wrapf("failed marshalling the request for creating a service ID: {{err}}", err)
	}

	r, err := http.NewRequest(http.MethodPost, h.getIAMURL(v1APIKeys), bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return nil, err
	}

	if httpStatus != 201 {
		return nil, fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	keyInfo := new(APIKeyV1Response)

	if err := json.Unmarshal(body, &keyInfo); err != nil {
		return nil, err
	}

	if len(keyInfo.APIKey) == 0 {
		return nil, fmt.Errorf("an empty API key was returned with code %v and response %v", httpStatus, string(body))
	}
	if len(keyInfo.ID) == 0 {
		return nil, fmt.Errorf("API key with an empty ID was returned with code %v and response %v", httpStatus, string(body))
	}
	return keyInfo, nil
}

func (h *ibmCloudHelper) DeleteAPIKey(iamToken, apiKeyID string) error {
	r, err := http.NewRequest(http.MethodDelete, h.getIAMURL(v1APIKeysID, apiKeyID), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return err
	}

	if httpStatus != 204 {
		return fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	return nil
}

func (h *ibmCloudHelper) GetAPIKeyDetails(iamToken, apiKeyValue string) (*APIKeyDetailsResponse, error) {
	r, err := http.NewRequest(http.MethodGet, h.getIAMURL(v1APIKeyDetails), nil)
	if err != nil {
		return nil, errwrap.Wrapf("failed creating http request: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("IAM-Apikey", apiKeyValue)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(h.httpClient, r)
	if err != nil {
		return nil, err
	}

	keyDetails := new(APIKeyDetailsResponse)

	if err := json.Unmarshal(body, &keyDetails); err != nil {
		return nil, err
	}

	if httpStatus != 200 {
		return nil, fmt.Errorf("unexpected http status code: %v with response %v", httpStatus, string(body))
	}
	return keyDetails, nil
}

func (h *ibmCloudHelper) getURL(endpoint, path string, pathReplacements ...string) string {
	pathSubs := make([]interface{}, len(pathReplacements))
	for i, v := range pathReplacements {
		pathSubs[i] = v
	}
	return fmt.Sprintf("%s%s", endpoint, fmt.Sprintf(path, pathSubs...))
}

func (h *ibmCloudHelper) getIAMURL(path string, pathReplacements ...string) string {
	return h.getURL(h.iamEndpoint, path, pathReplacements...)
}

func (h *ibmCloudHelper) getUserManagementURL(path string, pathReplacements ...string) string {
	return h.getURL(h.userManagementEndpoint, path, pathReplacements...)
}
