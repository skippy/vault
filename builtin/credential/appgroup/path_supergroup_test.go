package appgroup

import (
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestBackend_supergroup_secret_id(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	appData := map[string]interface{}{
		"policies":      "p,q,r,s",
		"num_uses":      10,
		"secret_id_ttl": 300,
		"token_ttl":     400,
		"token_max_ttl": 500,
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
		"num_uses":            11,
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

	superGroupData := map[string]interface{}{
		"groups":              "group1",
		"apps":                "app1",
		"additional_policies": "x,y,z",
		"num_uses":            122,
		"secret_id_ttl":       302,
		"token_ttl":           402,
		"token_max_ttl":       502,
	}

	superGroupSecretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "supergroup/secret-id",
		Storage:   storage,
		Data:      superGroupData,
	}
	resp, err = b.HandleRequest(superGroupSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id"].(string) == "" {
		t.Fatalf("failed to generate secret_id")
	}

	superGroupSecretIDReq.Path = "supergroup/custom-secret-id"
	superGroupData["secret_id"] = "abcd123"
	resp, err = b.HandleRequest(superGroupSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Data["secret_id"] != "abcd123" {
		t.Fatalf("failed to set specific secret_id to supergroup")
	}
}
