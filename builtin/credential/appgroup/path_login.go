package appgroup

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"selector": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Identifier of the category the SecretID belongs to.",
			},
			"secret_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "SecretID of the App.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLoginUpdate,
		},
		HelpSynopsis:    pathLoginHelpSys,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *backend) pathLoginRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	selectorType := req.Auth.InternalData["selector_type"].(string)
	selectorValue := req.Auth.InternalData["selector_value"].(string)
	if selectorType == "" || selectorValue == "" {
		return nil, fmt.Errorf("failed to fetch selector type and/or selector value during renewal")
	}
	resp, err := b.validateSelector(req.Storage, selectorType, selectorValue)
	if err != nil {
		return nil, fmt.Errorf("failed to validate selector during renewal:%s", err)
	}

	return framework.LeaseExtend(resp.TokenTTL, resp.TokenMaxTTL, b.System())(req, data)
}

func (b *backend) pathLoginUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretID := strings.TrimSpace(data.Get("secret_id").(string))
	if secretID == "" {
		return logical.ErrorResponse("missing secret_id"), nil
	}

	// Selector can optionally be prepended to the SecretID with a `;` delimiter
	selector := strings.TrimSpace(data.Get("selector").(string))
	if selector == "" {
		selectorFields := strings.SplitN(secretID, ";", 2)
		if len(selectorFields) != 2 || selectorFields[0] == "" {
			return logical.ErrorResponse("missing selector"), nil
		} else if selectorFields[1] == "" {
			return logical.ErrorResponse("missing secret_id"), nil
		} else {
			selector = selectorFields[0]
			secretID = selectorFields[1]
		}
	}

	validateResp, err := b.validateCredentials(req.Storage, selector, secretID)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to validate secret ID: %s", err)), nil
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"selector_type":  validateResp.SelectorType,
				"selector_value": validateResp.SelectorValue,
			},
			Policies: validateResp.Policies,
			LeaseOptions: logical.LeaseOptions{
				TTL:       validateResp.TokenTTL,
				Renewable: true,
			},
		},
	}
	return resp, nil
}

const pathLoginHelpSys = "Issue a token for a given pair of 'selector' and 'secret_id'."

const pathLoginHelpDesc = `The supplied SecretID could've been generated/assigned against an
individual App, or a Group or a 'supergroup' combination of both.
The respective 'selector' for these categories of SecretIDs are
'app/<app_name>', 'group/<group_name>' or 'supergroup'. The supplied
credentials <'selector','secret_id'> are validated and a Vault token
is issued with effective capabilities to access the participating
Apps.
`
