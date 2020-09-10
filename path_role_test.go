package iam_plugin

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Defaults for verifying response data. If a value is not included here, it must be included in the
// 'expected' map param for a test.
var expectedDefaults = map[string]interface{}{
	"token_policies":          []string{},
	"token_ttl":               int64(0),
	"token_max_ttl":           int64(0),
	"max_ttl":                 int64(0),
	"token_period":            int64(0),
	"token_explicit_max_ttl":  int64(0),
	"token_no_default_policy": false,
	"token_bound_cidrs":       []string{},
	"token_num_uses":          int(0),
	"token_type":              logical.TokenTypeDefault.String(),
	"bound_subjects":          []string{},
	"bound_access_groups":     []string{},
}

//Test roles with subject lists
func TestRoleSubjectList(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)
	roleName := testRole(t)
	boundSubs := []string{"testUser@test.com", "serviceID1", "serviceID2"}

	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":           roleName,
		"bound_subjects": strings.Join(boundSubs, ","),
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":                   roleName,
		"bound_subjects":         boundSubs,
		"bound_access_group_ids": []string{},
	})

	boundSubs = append(boundSubs, "anotheruser@example.com")
	testRoleUpdate(t, b, reqStorage, map[string]interface{}{
		"name":           roleName,
		"token_policies": "dev",
		"token_ttl":      1000,
		"token_max_ttl":  2000,
		"token_period":   30,
		"bound_subjects": strings.Join(boundSubs, ","),
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"token_policies":         []string{"dev"},
		"token_ttl":              int64(1000),
		"token_max_ttl":          int64(2000),
		"token_period":           int64(30),
		"bound_subjects":         boundSubs,
		"bound_access_group_ids": []string{},
	})

}

//Test roles with access groups lists
func TestRoleAccessGroupList(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)
	roleName := testRole(t)
	boundGroups := []string{"AccessGroupId-1b5dcd00-5f78-4bb1-a0a0-9629fe1d0b10", "AccessGroupId-1b5dcd00-5b68-4bb1-a0a0-9629fe1d0b12", "AccessGroupId-1a4dcd00-5f78-4bb1-a0a0-9629fe1d0b12"}

	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"bound_access_group_ids": strings.Join(boundGroups, ","),
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":                   roleName,
		"bound_subjects":         []string{},
		"bound_access_group_ids": boundGroups,
	})
	boundGroups = append(boundGroups, "anotherGroup")
	testRoleUpdate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"token_policies":         "dev",
		"token_ttl":              1000,
		"token_max_ttl":          2000,
		"token_period":           30,
		"bound_access_group_ids": strings.Join(boundGroups, ","),
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"token_policies":         []string{"dev"},
		"token_ttl":              int64(1000),
		"token_max_ttl":          int64(2000),
		"token_period":           int64(30),
		"bound_subjects":         []string{},
		"bound_access_group_ids": boundGroups,
	})
}

//Test roles with a combination of subject and access groups lists
func TestRoleComboOfSubjectsAndAccessGroups(t *testing.T) {
	t.Parallel()

	b, reqStorage := testBackend(t)
	roleName := testRole(t)
	boundGroups := []string{"AccessGroupId-1b5dcd00-5f78-4bb1-a0a0-9629fe1d0b10", "AccessGroupId-1b5dcd00-5b68-4bb1-a0a0-9629fe1d0b12", "AccessGroupId-1a4dcd00-5f78-4bb1-a0a0-9629fe1d0b12"}
	boundSubs := []string{"testUser@test.com", "serviceID1", "serviceID2"}

	testRoleCreate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"bound_access_group_ids": strings.Join(boundGroups, ","),
		"bound_subjects":         strings.Join(boundSubs, ","),
	})

	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"name":                   roleName,
		"bound_subjects":         boundSubs,
		"bound_access_group_ids": boundGroups,
	})
	boundSubs = append(boundSubs, "anotherSubject@example.com")
	boundGroups = append(boundGroups, "anotherGroup")
	testRoleUpdate(t, b, reqStorage, map[string]interface{}{
		"name":                   roleName,
		"token_policies":         "dev",
		"token_ttl":              1000,
		"token_max_ttl":          2000,
		"token_period":           30,
		"bound_access_group_ids": strings.Join(boundGroups, ","),
		"bound_subjects":         strings.Join(boundSubs, ","),
	})
	testRoleRead(t, b, reqStorage, roleName, map[string]interface{}{
		"token_policies":         []string{"dev"},
		"token_ttl":              int64(1000),
		"token_max_ttl":          int64(2000),
		"token_period":           int64(30),
		"bound_subjects":         boundSubs,
		"bound_access_group_ids": boundGroups,
	})
}

func TestRoleCreateFailure(t *testing.T) {
	t.Parallel()
	roleName := testRole(t)

	b, reqStorage := testBackend(t)
	testRoleCreateError(t, b, reqStorage, map[string]interface{}{
		"name": roleName,
	},
		[]string{"must have at least one bound constraint"})
}

//-- Utils --
func testRoleCreate(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
}

func testRoleUpdate(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}
}

func testRoleCreateError(tb testing.TB, b logical.Backend, s logical.Storage, d map[string]interface{}, expected []string) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", d["name"]),
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		tb.Fatalf("expected error containing: %s", strings.Join(expected, ", "))
	}

	for _, str := range expected {
		if !strings.Contains(resp.Error().Error(), str) {
			tb.Fatalf("expected %s to be in error %v", str, resp.Error())
		}
	}
}

func testRoleRead(tb testing.TB, b logical.Backend, s logical.Storage, roleName string, expected map[string]interface{}) {
	tb.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Storage:   s,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		tb.Fatal(resp.Error())
	}

	if err := checkData(resp, expected, expectedDefaults); err != nil {
		tb.Fatal(err)
	}
}

func checkData(resp *logical.Response, expected map[string]interface{}, expectedDefault map[string]interface{}) error {
	for k, actualVal := range resp.Data {
		expectedVal, ok := expected[k]
		if !ok {
			expectedVal, ok = expectedDefault[k]
			if !ok {
				return fmt.Errorf("must provide expected value for %q for test", k)
			}
		}

		var isEqual bool
		switch actualVal.(type) {
		case []string:
			actual := actualVal.([]string)
			expected, ok := expectedVal.([]string)
			if !ok {
				return fmt.Errorf("%s type mismatch: expected type %T, actual type %T", k, expectedVal, actualVal)
			}
			isEqual = (len(actual) == 0 && len(expected) == 0) ||
				strutil.EquivalentSlices(actual, expected)
		case map[string]string:
			actual := actualVal.(map[string]string)
			expected, ok := expectedVal.(map[string]string)
			if !ok {
				return fmt.Errorf("%s type mismatch: expected type %T, actual type %T", k, expectedVal, actualVal)
			}
			isEqual = (len(actual) == 0 && len(expected) == 0) ||
				reflect.DeepEqual(actualVal, expectedVal)
		default:
			isEqual = actualVal == expectedVal
		}

		if !isEqual {
			return fmt.Errorf("%s mismatch, expected: %v but got %v", k, expectedVal, actualVal)
		}
	}
	return nil
}

// testRole generates a unique name for a role
func testRole(tb testing.TB) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	suffix := fmt.Sprintf("%d", r.Intn(1000000))

	roleName := "v-auth-" + suffix

	return roleName
}
