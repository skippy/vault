package approle

import (
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestBackend_role_login(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	createRole(t, b, storage, "role1", "a,b,c")
	roleSelectorIDReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/role1/selector-id",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(roleSelectorIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	selectorID := resp.Data["selector_id"]

	roleSecretIDReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "role/role1/secret-id",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(roleSecretIDReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}
	secretID := resp.Data["secret_id"]

	loginData := map[string]interface{}{
		"selector_id": selectorID,
		"secret_id":   secretID,
	}
	loginReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "login",
		Storage:   storage,
		Data:      loginData,
	}
	resp, err = b.HandleRequest(loginReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%v resp:%#v", err, resp)
	}

	if resp.Auth == nil {
		t.Fatalf("expected a non-nil auth object in the response")
	}
}
