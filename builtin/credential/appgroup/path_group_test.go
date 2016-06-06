package appgroup

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/mapstructure"
)

func TestBackend_group_secret_id_read_delete(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1", "a,b")
	createGroup(t, b, storage, "group1", "app1", "a,b")

	secretIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      "group/group1/secret-id",
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   storage,
		Path:      "group/group1/secret-id",
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	hmacSecretID := resp.Data["keys"].([]string)[0]
	shards := strings.Split(hmacSecretID, "/")
	hmacSecretID = shards[len(shards)-1]

	hmacReq := &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      "group/group1/secret-id/" + hmacSecretID,
	}
	resp, err = b.HandleRequest(hmacReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	result := secretIDStorageEntry{}
	if err := mapstructure.Decode(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	hmacReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(hmacReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	hmacReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(hmacReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	if resp != nil {
		t.Fatalf("expected a nil response")
	}
}

func TestBackend_group_list_secret_id(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1", "a,b")
	createGroup(t, b, storage, "group1", "", "a,b")

	secretIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      "group/group1/secret-id",
	}
	// Create 5 'secret_id's
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   storage,
		Path:      "group/group1/secret-id",
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	secrets := resp.Data["keys"].([]string)
	if len(secrets) != 5 {
		t.Fatalf("bad: len of secrets: expected:5 actual:%d", len(secrets))
	}
}

func TestBackend_group_list(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createGroup(t, b, storage, "group1", "", "a,b")
	createGroup(t, b, storage, "group2", "", "c,d")
	createGroup(t, b, storage, "group3", "", "e,f")
	createGroup(t, b, storage, "group4", "", "g,h")
	createGroup(t, b, storage, "group5", "", "i,j")

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "group",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	actual := resp.Data["keys"].([]string)
	expected := []string{"group/group1", "group/group2", "group/group3", "group/group4", "group/group5"}
	if !policyutil.EquivalentPolicies(actual, expected) {
		t.Fatalf("bad: listed groups: expected:%s\nactual:%s", expected, actual)
	}
}

func TestBackend_group_secret_id(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	appData := map[string]interface{}{
		"policies":           "p,q,r,s",
		"secret_id_num_uses": 10,
		"secret_id_ttl":      300,
		"token_ttl":          400,
		"token_max_ttl":      500,
	}
	appReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "app/app1",
		Storage:   storage,
		Data:      appData,
	}

	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupData := map[string]interface{}{
		"apps":                "app1",
		"additional_policies": "t,u,v,w",
		"secret_id_num_uses":  11,
		"secret_id_ttl":       301,
		"token_ttl":           401,
		"token_max_ttl":       501,
	}

	groupReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "group/group1",
		Storage:   storage,
		Data:      groupData,
	}

	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupSecretIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "group/group1/secret-id",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(groupSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id"].(string) == "" {
		t.Fatalf("failed to generate secret_id")
	}

	groupSecretIDReq.Path = "group/group1/custom-secret-id"
	groupCustomSecretIDData := map[string]interface{}{
		"secret_id": "abcd123",
	}
	groupSecretIDReq.Data = groupCustomSecretIDData
	groupSecretIDReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(groupSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id"] != "abcd123" {
		t.Fatalf("failed to set specific secret_id to group")
	}
}
func TestBackend_group_CRUD(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	groupData := map[string]interface{}{
		"apps":                "app1,app2",
		"additional_policies": "p,q,r,s",
		"secret_id_num_uses":  10,
		"secret_id_ttl":       300,
		"token_ttl":           400,
		"token_max_ttl":       500,
	}
	groupReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "group/group1",
		Storage:   storage,
		Data:      groupData,
	}

	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	expected := map[string]interface{}{
		"bind_secret_id":      true,
		"apps":                []string{"app1", "app2"},
		"additional_policies": []string{"default", "p", "q", "r", "s"},
		"secret_id_num_uses":  10,
		"secret_id_ttl":       300,
		"token_ttl":           400,
		"token_max_ttl":       500,
	}
	var expectedStruct appStorageEntry
	err = mapstructure.Decode(expected, &expectedStruct)
	if err != nil {
		t.Fatal(err)
	}

	var actualStruct appStorageEntry
	err = mapstructure.Decode(resp.Data, &actualStruct)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedStruct, actualStruct) {
		t.Fatalf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)
	}

	groupData = map[string]interface{}{
		"apps":                "app11,app21",
		"additional_policies": "a,b,c,d",
		"secret_id_num_uses":  100,
		"secret_id_ttl":       3000,
		"token_ttl":           4000,
		"token_max_ttl":       5000,
	}
	groupReq.Data = groupData
	groupReq.Operation = logical.UpdateOperation

	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	expected = map[string]interface{}{
		"apps":                []string{"app11", "app21"},
		"additional_policies": []string{"a", "b", "c", "d", "default"},
		"secret_id_num_uses":  100,
		"secret_id_ttl":       3000,
		"token_ttl":           4000,
		"token_max_ttl":       5000,
	}
	err = mapstructure.Decode(expected, &expectedStruct)
	if err != nil {
		t.Fatal(err)
	}

	err = mapstructure.Decode(resp.Data, &actualStruct)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expectedStruct, actualStruct) {
		t.Fatalf("bad:\nexpected:%#v\nactual:%#v\n", expectedStruct, actualStruct)
	}

	// RUD for apps field
	groupReq.Path = "group/group1/apps"
	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Data = map[string]interface{}{"apps": "application1,application2"}
	groupReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if !reflect.DeepEqual(resp.Data["apps"].([]string), []string{"application1", "application2"}) {
		t.Fatalf("bad: apps: actual:%s\n", resp.Data["apps"].([]string))
	}
	groupReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["apps"].([]string) != nil {
		t.Fatalf("expected value to be reset")
	}

	// RUD for bind_secret_id field
	groupReq.Path = "group/group1/bind-secret-id"
	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Data = map[string]interface{}{"bind_secret_id": false}
	groupReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["bind_secret_id"].(bool) {
		t.Fatalf("bad: bind_secret_id: expected:false actual:%t\n", resp.Data["bind_secret_id"].(bool))
	}
	groupReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["bind_secret_id"].(bool) {
		t.Fatalf("expected value to be reset")
	}

	// RUD for additional_policiess field
	groupReq.Path = "group/group1/additional-policies"
	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Data = map[string]interface{}{"additional_policies": "a1,b1,c1,d1"}
	groupReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if !reflect.DeepEqual(resp.Data["additional_policies"].([]string), []string{"a1", "b1", "c1", "d1", "default"}) {
		t.Fatalf("bad: additional_policies: actual:%s\n", resp.Data["additional_policies"].([]string))
	}
	groupReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["additional_policies"].([]string) != nil {
		t.Fatalf("expected value to be reset")
	}

	// RUD for num-uses field
	groupReq.Path = "group/group1/num-uses"
	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Data = map[string]interface{}{"secret_id_num_uses": 200}
	groupReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_num_uses"].(int) != 200 {
		t.Fatalf("bad: secret_id_num_uses: expected:200 actual:%d\n", resp.Data["secret_id_num_uses"].(int))
	}
	groupReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_num_uses"].(int) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for secret_id_ttl field
	groupReq.Path = "group/group1/secret_id-ttl"
	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Data = map[string]interface{}{"secret_id_ttl": 3001}
	groupReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_ttl"].(time.Duration) != 3001 {
		t.Fatalf("bad: secret_id_ttl: expected:3001 actual:%d\n", resp.Data["secret_id_ttl"].(time.Duration))
	}
	groupReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for token_ttl field
	groupReq.Path = "group/group1/token-ttl"
	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Data = map[string]interface{}{"token_ttl": 4001}
	groupReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_ttl"].(time.Duration) != 4001 {
		t.Fatalf("bad: token_ttl: expected:4001 actual:%d\n", resp.Data["token_ttl"].(time.Duration))
	}
	groupReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for token_max_ttl field
	groupReq.Path = "group/group1/token-max-ttl"
	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Data = map[string]interface{}{"token_max_ttl": 5001}
	groupReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_max_ttl"].(time.Duration) != 5001 {
		t.Fatalf("bad: token_max_ttl: expected:5001 actual:%d\n", resp.Data["token_max_ttl"].(time.Duration))
	}
	groupReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_max_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// Delete test for group
	groupReq.Path = "group/group1"
	groupReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	groupReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp != nil {
		t.Fatalf("expected a nil response")
	}
}

func createGroup(t *testing.T, b *backend, s logical.Storage, groupName, apps, additionalPolicies string) {
	groupData := map[string]interface{}{
		"apps":                apps,
		"additional_policies": additionalPolicies,
		"secret_id_num_uses":  10,
		"secret_id_ttl":       300,
		"token_ttl":           400,
		"token_max_ttl":       500,
	}
	groupReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "group/" + groupName,
		Storage:   s,
		Data:      groupData,
	}

	resp, err := b.HandleRequest(groupReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

}
