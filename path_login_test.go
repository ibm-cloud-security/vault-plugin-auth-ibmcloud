package ibmcloudauth

import (
	"context"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

/**
 This file tests the login path of the auth method. It uses a mock implementation of the iamHelper interface to
 allow testing of a set configuration of users, service IDs, and access groups. This allows unit testing without needing
 to create a test environment in IBM Cloud.

 The tests uses gomock with the iamHelper mock being created by mockgen:
	$ mockgen -destination mocks_test.go -source iam_helper.go -package ibmcloudauth

 The configuration configured by theses tests and enforced by the mock is:
	Users / Service IDs:
		user1: a user with access to the account configured on the backend. Can login with testRole1.
		user2: a user with access to the account configured on the backend. Can login with testRole1.
		user3: a user with access to the account configured on the backend. Can login with testRole2.
		user4: a service ID with access to the account configured on the backend. Can login with testRole2.
		user5: a user without access to the account configured on the backend.
		user6: a service ID without access to the account configured on the backend.

	Roles:
		testRole1: utilizes the bound subject ID list. user1 and user2 are members
		testRole2: utilizes the bound access group lists, binds to groups group1, 2, and 3, users3 and 4 can log in
*/

// Roles for login testing
func getTestRoles() map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		"testRole1": {
			"name":           "testRole1",
			"bound_subjects": []string{"user1", "user2"},
			"token_policies": []string{"dev", "test"},
		},
		"testRole2": {
			"name":                   "testRole2",
			"bound_access_group_ids": []string{"group1", "group2", "group3"},
			"token_policies":         []string{"managers", "operators"},
		},
	}
}

/*
	This function configures the mock iamHelper expectations for the test. It then creates a test Backend with
	with the mock, configures it, and creates the test roles. The configuration enforced by the mock iamHelper is
	described in the header comment block of this file.

	The loginUserToken tokenInfo parameter should specify the user that will be used for the login test.

	The minCalls map is used to control the minimum number of times the functions of the iamHelper interface are
	expected to be called. The keys are the function names (e.g. "ObtainToken", "CheckUserIDAccount", etc).
	If unspecified 0 is used.
*/
func getMockedBackend(t *testing.T, loginUserTokenInfo *tokenInfo, ctrl *gomock.Controller, callCount map[string]int) (*ibmCloudAuthBackend, logical.Storage) {
	t.Helper()

	var configData = map[string]interface{}{
		"api_key":    "adminKey",
		"account_id": "theAccountID",
	}

	mockHelper := NewMockiamHelper(ctrl)
	// For the adminKey we always return AdminToken, this lets enforce that the code is correctly using the admin token
	// for the Check* calls.
	mockHelper.EXPECT().ObtainToken("adminKey").Return("AdminToken", nil)
	if callCount["ObtainToken"] > 1 {
		// used for the API key login path
		mockHelper.EXPECT().ObtainToken("user1APIKey").Return("userToken", nil)
	}

	mockHelper.EXPECT().VerifyToken(gomock.Any(), "AdminToken").Return(&tokenInfo{}, nil)
	mockHelper.EXPECT().VerifyToken(gomock.Any(), gomock.Not(gomock.Eq("AdminToken"))).
		DoAndReturn(func(ctx context.Context, token string) (*tokenInfo, *logical.Response) {
			if token == "userToken" { // for test purposes we expect all user tokens to be "userToken"
				return loginUserTokenInfo, nil
			}
			return nil, logical.ErrorResponse("mock VerifyToken, invalid token: %s", token)
		})
	mockHelper.EXPECT().CheckUserIDAccount("AdminToken", loginUserTokenInfo.IAMid, "theAccountID").
		Times(callCount["CheckUserIDAccount"]).DoAndReturn(func(iamToken, iamID, accountID string) error {
		if !strutil.StrListContains([]string{"iamID1", "iamID2", "iamID3"}, iamID) {
			return fmt.Errorf("mock CheckUserIDAccount: user not in account: %s", iamID)
		}
		return nil
	})
	mockHelper.EXPECT().CheckServiceIDAccount("AdminToken", loginUserTokenInfo.Identifier, "theAccountID").
		Times(callCount["CheckServiceIDAccount"]).DoAndReturn(func(iamToken, identifier, accountID string) error {
		if !strutil.StrListContains([]string{"user4Identifier"}, identifier) {
			return fmt.Errorf("mock CheckServiceIDAccount: serviceID not in account: %s", identifier)
		}
		return nil
	})

	mockHelper.EXPECT().CheckGroupMembership(gomock.Any(), loginUserTokenInfo.IAMid, "AdminToken").
		Times(callCount["CheckGroupMembership"]).DoAndReturn(func(groupID, iamID, iamToken string) error {
		// check access group "group3" members:
		if groupID == "group3" && strutil.StrListContains([]string{"iamID3", "iamID4"}, iamID) {
			return nil
		}
		return fmt.Errorf("mock CheckGroupMembership: user %s not in group: %s", iamID, groupID)
	})

	b, s := testBackendWithMock(t, mockHelper)
	err := testConfigCreate(t, b, s, configData)
	if err != nil {
		t.Fatal("error configuring the backend")
	}

	for _, data := range getTestRoles() {
		testRoleCreate(t, b, s, data)
	}

	return b, s
}

// Test a successful login when the user is in a bound subject list
func TestLoginSuccessUserInList(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ti := tokenInfo{
		IAMid:       "iamID1",
		SubjectType: "n/a",
		Subject:     "user1",
	}
	callCounts := map[string]int{
		"CheckUserIDAccount": 1,
	}

	b, s := getMockedBackend(t, &ti, ctrl, callCounts)

	var loginData = map[string]interface{}{
		"token": "userToken",
		"role":  "testRole1",
	}

	if err := testLoginSuccessful(t, b, s, ti, loginData, getTestRoles()["testRole1"]); err != nil {
		t.Fatal(err)
	}
}

// Test a successful login when using an API key
func TestLoginAPIKey(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ti := tokenInfo{
		IAMid:       "iamID1",
		SubjectType: "n/a",
		Subject:     "user1",
	}
	callCounts := map[string]int{
		"CheckUserIDAccount": 1,
		"ObtainToken":        2,
	}

	b, s := getMockedBackend(t, &ti, ctrl, callCounts)

	var loginData = map[string]interface{}{
		"api_key": "user1APIKey",
		"role":    "testRole1",
	}

	if err := testLoginSuccessful(t, b, s, ti, loginData, getTestRoles()["testRole1"]); err != nil {
		t.Fatal(err)
	}
}

// Test a successful login when the user is in a bound access group
func TestLoginSuccessUserInGroup(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ti := tokenInfo{
		IAMid:       "iamID3",
		SubjectType: "n/a",
		Subject:     "user3",
	}
	callCounts := map[string]int{
		"CheckUserIDAccount":   1,
		"CheckGroupMembership": 3,
	}
	b, s := getMockedBackend(t, &ti, ctrl, callCounts)

	var loginData = map[string]interface{}{
		"token": "userToken",
		"role":  "testRole2",
	}

	if err := testLoginSuccessful(t, b, s, ti, loginData, getTestRoles()["testRole2"]); err != nil {
		t.Fatal(err)
	}
}

/* Test a successful login when a service ID user is in a bound access group
   This tests both service IDs being a group, but also tests the service ID access to
   the configured account path.
*/
func TestLoginSuccessServiceIDInGroup(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ti := tokenInfo{
		IAMid:       "iamID4",
		SubjectType: serviceIDSubjectType,
		Subject:     "user4",
		Identifier:  "user4Identifier",
	}
	callCounts := map[string]int{
		"CheckServiceIDAccount": 1,
		"CheckGroupMembership":  3,
	}

	b, s := getMockedBackend(t, &ti, ctrl, callCounts)

	var loginData = map[string]interface{}{
		"token": "userToken",
		"role":  "testRole2",
	}

	if err := testLoginSuccessful(t, b, s, ti, loginData, getTestRoles()["testRole2"]); err != nil {
		t.Fatal(err)
	}
}

// Test a failed login when a user is not in a bound access group or a bound subject list
func TestLoginFailureUserNotInGroup(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ti := tokenInfo{
		IAMid:       "iamID1",
		SubjectType: "n/a",
		Subject:     "user1",
	}
	callCounts := map[string]int{
		"CheckUserIDAccount":   1,
		"CheckGroupMembership": 3,
	}
	b, s := getMockedBackend(t, &ti, ctrl, callCounts)

	var loginData = map[string]interface{}{
		"token": "userToken",
		"role":  "testRole2",
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      loginData,
		Storage:   s,
	})

	if resp != nil {
		t.Fatal("Received unexpected resp", resp)
	}
	if err != logical.ErrPermissionDenied {
		t.Fatal("Expected ErrPermissionDenied, received:", err)
	}
}

// Test a failed login when a user does not have access to the configured account.
func TestLoginFailureUserNoAccountAccess(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ti := tokenInfo{
		IAMid:       "iamID5",
		SubjectType: "n/a",
		Subject:     "user5",
	}
	callCounts := map[string]int{
		"CheckUserIDAccount": 1,
	}
	b, s := getMockedBackend(t, &ti, ctrl, callCounts)

	var loginData = map[string]interface{}{
		"token": "userToken",
		"role":  "testRole1",
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      loginData,
		Storage:   s,
	})

	if resp != nil {
		t.Fatal("Received unexpected resp", resp)
	}
	if err != logical.ErrPermissionDenied {
		t.Fatal("Expected ErrPermissionDenied, received:", err)
	}
}

// Test a failed login when a serviceID does not have access to the configured account.
func TestLoginFailureServiceIDNoAccountAccess(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ti := tokenInfo{
		IAMid:       "iamID6",
		SubjectType: serviceIDSubjectType,
		Identifier:  "user6Identifier",
		Subject:     "user6",
	}
	callCounts := map[string]int{
		"CheckServiceIDAccount": 1,
	}
	b, s := getMockedBackend(t, &ti, ctrl, callCounts)

	var loginData = map[string]interface{}{
		"token": "userToken",
		"role":  "testRole1",
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      loginData,
		Storage:   s,
	})

	if resp != nil {
		t.Fatal("Received unexpected resp", resp)
	}
	if err != logical.ErrPermissionDenied {
		t.Fatal("Expected ErrPermissionDenied, received:", err)
	}
}

// Test a failed login when a serviceID does not have access to the configured account.
func TestLoginFailureInvalidToken(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ti := tokenInfo{
		IAMid:   "iamID1",
		Subject: "user1",
	}
	callCounts := map[string]int{}
	b, s := getMockedBackend(t, &ti, ctrl, callCounts)

	var loginData = map[string]interface{}{
		"token": "badUserToken",
		"role":  "testRole1",
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      loginData,
		Storage:   s,
	})

	if resp == nil || !resp.IsError() {
		t.Fatal("expected an error resp, got ", resp)
	}
	if err != nil {
		t.Fatal(fmt.Errorf("err: %v", err))
	}

	errMsg := resp.Data["error"].(string)
	if !strings.Contains(errMsg, "invalid token") {
		t.Fatal("expect an invalid token message. received: ", errMsg)
	}
}

// Test that login fails if the configuration is not set
func TestLoginConfigNotSet(t *testing.T) {
	t.Parallel()
	b, s := testBackend(t)
	roleName := "testRole"
	roleData := map[string]interface{}{
		"name":           roleName,
		"bound_subjects": []string{"user1", "user2"},
	}
	testRoleCreate(t, b, s, roleData)

	var loginData = map[string]interface{}{
		"token": "abc",
		"role":  "testRole",
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      loginData,
		Storage:   s,
	})
	if err == nil {
		t.Fatal("No error was thrown when login was attempted with out config")
	}
	if resp != nil {
		t.Fatal("unexpected", resp)
	}
}

func testLoginSuccessful(t *testing.T, b *ibmCloudAuthBackend, s logical.Storage, ti tokenInfo, loginData, roleData map[string]interface{}) error {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      loginData,
		Storage:   s,
	})
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}
	if resp.IsError() {
		return fmt.Errorf(resp.Error().Error())
	}
	if resp.Auth == nil {
		return fmt.Errorf("received nil auth data")
	}
	if resp.Auth.Metadata == nil {
		return fmt.Errorf("received nil auth metadata data")
	}

	expectedMeta := map[string]string{
		iamIDField:       ti.IAMid,
		subjectField:     ti.Subject,
		subjectTypeField: ti.SubjectType,
		identifierField:  ti.Identifier,
		roleField:        roleData["name"].(string),
	}
	assert.Equal(t, expectedMeta, resp.Auth.Metadata)

	if !policyutil.EquivalentPolicies(resp.Auth.Policies, roleData["token_policies"].([]string)) {
		return fmt.Errorf("policy mismatch, expected %v but got %v", roleData["policies"].([]string), resp.Auth.Policies)
	}
	return nil
}
