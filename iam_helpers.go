package ibmcloudauth

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/errwrap"
	"net/http"
	"net/url"
	"strings"
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

func checkGroupMembership(client *http.Client, groupID, iamID, iamToken string) error {
	r, err := http.NewRequest(http.MethodHead, getURL(iamEndpointFieldDefault, accessGroupMembershipCheck, groupID, iamID), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request for creating policy: {{err}}", err)
	}

	r.Header.Set("Authorization", iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")

	_, err = httpRequestCheckStatus(client, r, http.StatusNoContent)
	return err
}

/**
Obtain an IAM token by way of an API Key
*/
func obtainToken(client *http.Client, endpoint, apiKey string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Set("apikey", apiKey)
	data.Set("response_type", "cloud_iam")

	req, err := http.NewRequest(http.MethodPost, endpoint+"/token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", errwrap.Wrapf("Error creating obtain token request: {{err}}", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
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

func checkServiceIDAccount(client *http.Client, iamToken, identifier, accountID string) error {
	r, err := http.NewRequest(http.MethodGet, getURL(iamEndpointFieldDefault, serviceIDDetails, identifier), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request for creating policy: {{err}}", err)
	}

	r.Header.Set("Authorization", "Bearer "+iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	body, httpStatus, err := httpRequest(client, r)
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

func checkUserIDAccount(client *http.Client, iamToken, iamID, accountID string) error {
	r, err := http.NewRequest(http.MethodGet, getURL(userMgmtEndpointDefault, getUserProfile, accountID, iamID), nil)
	if err != nil {
		return errwrap.Wrapf("failed creating http request for creating policy: {{err}}", err)
	}

	r.Header.Set("Authorization", iamToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	_, err = httpRequestCheckStatus(client, r, http.StatusOK)
	return err
}
