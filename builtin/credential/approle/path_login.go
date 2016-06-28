package approle

import (
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"selector_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Unique identifier of the App. Required to be supplied when the bind type is 'bind_secret_id'",
			},
			"secret_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "",
				Description: "SecretID of the App",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathLoginUpdate,
		},
		HelpSynopsis:    pathLoginHelpSys,
		HelpDescription: pathLoginHelpDesc,
	}
}

// Returns the Auth object indicating the authentication and authorization information
// if the credentials provided are validated by the backend.
func (b *backend) pathLoginUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	app, err := b.validateCredentials(req, data)
	if err != nil || app == nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to validate SecretID: %s", err)), nil
	}

	auth := &logical.Auth{
		Period: app.Period,
		InternalData: map[string]interface{}{
			"selector_id": app.SelectorID,
		},
		Policies: app.Policies,
		LeaseOptions: logical.LeaseOptions{
			Renewable: true,
		},
	}

	// If 'Period' is set, use the value of 'Period' as the TTL.
	// Otherwise, set the normal TokenTTL.
	if app.Period > time.Duration(0) {
		auth.TTL = app.Period
	} else {
		auth.TTL = app.TokenTTL
	}

	return &logical.Response{
		Auth: auth,
	}, nil
}

// Invoked when the token issued by this backend is attempting a renewal.
func (b *backend) pathLoginRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	selectorID := req.Auth.InternalData["selector_id"].(string)
	if selectorID == "" {
		return nil, fmt.Errorf("failed to fetch selector_id during renewal")
	}

	// Ensure that the App still exists.
	app, err := b.validateSelectorID(req.Storage, selectorID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate selector during renewal:%s", err)
	}

	// If 'Period' is set on the App, the token should never expire.
	// Replenish the TTL with 'Period's value.
	if app.Period > time.Duration(0) {
		// If 'Period' was updated after the token was issued,
		// token will bear the updated 'Period' value as its TTL.
		req.Auth.TTL = app.Period
		return &logical.Response{Auth: req.Auth}, nil
	} else {
		return framework.LeaseExtend(app.TokenTTL, app.TokenMaxTTL, b.System())(req, data)
	}
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
