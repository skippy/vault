package appgroup

import (
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/mapstructure"
)

func TestBackend_app_delete_secret_id(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1", "a,b")
	secretIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      "app/app1/secret-id",
	}
	// Create 3 secrets on the app
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
		Path:      "app/app1/secret-id",
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	hashedSecrets := resp.Data["keys"].([]string)
	if len(hashedSecrets) != 3 {
		t.Fatalf("bad: len of hashedSecrets: expected:3 actual:%d", len(hashedSecrets))
	}

	appReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Storage:   storage,
		Path:      "app/app1",
	}
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || resp == nil || (resp != nil && !resp.IsError()) {
		t.Fatalf("expected an error. err:%v resp:%#v", err, resp)
	}
}

func TestBackend_app_secret_id_read_delete(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1", "a,b")
	secretIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      "app/app1/secret-id",
	}
	resp, err = b.HandleRequest(secretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Storage:   storage,
		Path:      "app/app1/secret-id",
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	hmacSecretID := resp.Data["keys"].([]string)[0]
	log.Printf("hmacSecretID: %s\n", hmacSecretID)

	hmacReq := &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      "app/app1/secret-id/" + hmacSecretID,
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

func TestBackend_app_list_secret_id(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1", "a,b")

	secretIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   storage,
		Path:      "app/app1/secret-id",
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
		Path:      "app/app1/secret-id/",
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

func TestBackend_app_list(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createApp(t, b, storage, "app1", "a,b")
	createApp(t, b, storage, "app2", "c,d")
	createApp(t, b, storage, "app3", "e,f")
	createApp(t, b, storage, "app4", "g,h")
	createApp(t, b, storage, "app5", "i,j")

	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "app",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(listReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	actual := resp.Data["keys"].([]string)
	expected := []string{"app1", "app2", "app3", "app4", "app5"}
	if !policyutil.EquivalentPolicies(actual, expected) {
		t.Fatalf("bad: listed apps: expected:%s\nactual:%s", expected, actual)
	}
}

func TestBackend_app_secret_id(t *testing.T) {
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

	appSecretIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "app/app1/secret-id",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(appSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id"].(string) == "" {
		t.Fatalf("failed to generate secret_id")
	}

	appSecretIDReq.Path = "app/app1/custom-secret-id"
	appCustomSecretIDData := map[string]interface{}{
		"secret_id": "abcd123",
	}
	appSecretIDReq.Data = appCustomSecretIDData
	appSecretIDReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id"] != "abcd123" {
		t.Fatalf("failed to set specific secret_id to app")
	}
}

func TestBackend_app_CRUD(t *testing.T) {
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

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	expected := map[string]interface{}{
		"bind_secret_id":     true,
		"policies":           []string{"default", "p", "q", "r", "s"},
		"secret_id_num_uses": 10,
		"secret_id_ttl":      300,
		"token_ttl":          400,
		"token_max_ttl":      500,
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

	appData = map[string]interface{}{
		"policies":           "a,b,c,d",
		"secret_id_num_uses": 100,
		"secret_id_ttl":      3000,
		"token_ttl":          4000,
		"token_max_ttl":      5000,
	}
	appReq.Data = appData
	appReq.Operation = logical.UpdateOperation

	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	expected = map[string]interface{}{
		"policies":           []string{"a", "b", "c", "d", "default"},
		"secret_id_num_uses": 100,
		"secret_id_ttl":      3000,
		"token_ttl":          4000,
		"token_max_ttl":      5000,
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

	// RUD for bind_secret_id field
	appReq.Path = "app/app1/bind-secret-id"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Data = map[string]interface{}{"bind_secret_id": false}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["bind_secret_id"].(bool) {
		t.Fatalf("bad: bind_secret_id: expected:false actual:%t\n", resp.Data["bind_secret_id"].(bool))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["bind_secret_id"].(bool) {
		t.Fatalf("expected value to be reset")
	}

	// RUD for policiess field
	appReq.Path = "app/app1/policies"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Data = map[string]interface{}{"policies": "a1,b1,c1,d1"}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if !reflect.DeepEqual(resp.Data["policies"].([]string), []string{"a1", "b1", "c1", "d1", "default"}) {
		t.Fatalf("bad: policies: actual:%s\n", resp.Data["policies"].([]string))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["policies"].([]string) != nil {
		t.Fatalf("expected value to be reset")
	}

	// RUD for num-uses field
	appReq.Path = "app/app1/num-uses"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Data = map[string]interface{}{"secret_id_num_uses": 200}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_num_uses"].(int) != 200 {
		t.Fatalf("bad: secret_id_num_uses: expected:200 actual:%d\n", resp.Data["secret_id_num_uses"].(int))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_num_uses"].(int) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for secret_id_ttl field
	appReq.Path = "app/app1/secret-id-ttl"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Data = map[string]interface{}{"secret_id_ttl": 3001}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_ttl"].(time.Duration) != 3001 {
		t.Fatalf("bad: secret_id_ttl: expected:3001 actual:%d\n", resp.Data["secret_id_ttl"].(time.Duration))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for token_ttl field
	appReq.Path = "app/app1/token-ttl"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Data = map[string]interface{}{"token_ttl": 4001}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_ttl"].(time.Duration) != 4001 {
		t.Fatalf("bad: token_ttl: expected:4001 actual:%d\n", resp.Data["token_ttl"].(time.Duration))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// RUD for token_max_ttl field
	appReq.Path = "app/app1/token-max-ttl"
	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Data = map[string]interface{}{"token_max_ttl": 5001}
	appReq.Operation = logical.UpdateOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_max_ttl"].(time.Duration) != 5001 {
		t.Fatalf("bad: token_max_ttl: expected:5001 actual:%d\n", resp.Data["token_max_ttl"].(time.Duration))
	}
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["token_max_ttl"].(time.Duration) != 0 {
		t.Fatalf("expected value to be reset")
	}

	// Delete test for app
	appReq.Path = "app/app1"
	appReq.Operation = logical.DeleteOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	appReq.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp != nil {
		t.Fatalf("expected a nil response")
	}
}

func createApp(t *testing.T, b *backend, s logical.Storage, appName, policies string) {
	appData := map[string]interface{}{
		"policies":           policies,
		"secret_id_num_uses": 10,
		"secret_id_ttl":      300,
		"token_ttl":          400,
		"token_max_ttl":      500,
	}
	appReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "app/" + appName,
		Storage:   s,
		Data:      appData,
	}

	resp, err := b.HandleRequest(appReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
}
