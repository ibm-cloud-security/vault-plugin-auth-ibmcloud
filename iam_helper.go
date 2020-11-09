package ibmcloudauth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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

type iamHelper interface {
	ObtainToken(apiKey string) (string, error)
	VerifyToken(ctx context.Context, token string) (*tokenInfo, *logical.Response)
	CheckServiceIDAccount(iamToken, identifier, accountID string) error
	CheckUserIDAccount(iamToken, iamID, accountID string) error
	CheckGroupMembership(groupID, iamID, iamToken string) error
	Init()
	Cleanup()
}

type ibmCloudHelper struct {
	providerLock      sync.RWMutex
	provider          *oidc.Provider
	providerCtx       context.Context
	providerCtxCancel context.CancelFunc
	httpClient        *http.Client
}

func (h *ibmCloudHelper) Init() {
	h.providerCtx, h.providerCtxCancel = context.WithCancel(context.Background())
	h.httpClient = cleanhttp.DefaultPooledClient()
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

	provider, err := oidc.NewProvider(h.providerCtx, iamIdentityEndpointDefault)
	if err != nil {
		return nil, errwrap.Wrapf("error creating provider with given values: {{err}}", err)
	}

	h.provider = provider
	return provider, nil
}

func (h *ibmCloudHelper) CheckGroupMembership(groupID, iamID, iamToken string) error {
	r, err := http.NewRequest(http.MethodHead, getURL(iamEndpointFieldDefault, accessGroupMembershipCheck, groupID, iamID), nil)
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

	req, err := http.NewRequest(http.MethodPost, iamIdentityEndpointDefault+"/token", strings.NewReader(data.Encode()))
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
		return nil, logical.ErrorResponse("unable to successfully parse all claims from token: %s", err)
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
	r, err := http.NewRequest(http.MethodGet, getURL(iamEndpointFieldDefault, serviceIDDetails, identifier), nil)
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
	r, err := http.NewRequest(http.MethodGet, getURL(userMgmtEndpointDefault, getUserProfile, accountID, iamID), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request for creating policy: {{err}}", err)
	}

	r.Header.Set("Authorization", iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	_, err = httpRequestCheckStatus(h.httpClient, r, http.StatusOK)
	return err
}
