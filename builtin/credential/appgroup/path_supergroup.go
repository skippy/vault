package appgroup

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// superGroupStorageEntry stores all the options that are set during UserID
// creation in "supergroup" mode.
type superGroupStorageEntry struct {
	// All the Groups that are to be accessible by the UserID created
	Groups []string `json:"groups" structs:"groups" mapstructure:"groups"`

	// All the Apps that are to be accessible by the UserID created
	Apps []string `json:"apps" structs:"apps" mapstructure:"apps"`

	// Number of times the generated UserID can be used to perform login
	NumUses int `json:"num_uses" structs:"num_uses" mapstructure:"num_uses"`

	// Duration (less than the backend mount's max TTL) after which a UserID generated will expire
	UserIDTTL time.Duration `json:"userid_ttl" structs:"userid_ttl" mapstructure:"userid_ttl"`

	// Duration before which an issued token must be renewed
	TokenTTL time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`

	// Duration after which an issued token should not be allowed to be renewed
	TokenMaxTTL time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`

	// Along with the combined set of Apps' and Groups' policies, the policies in this
	// list will be added to capabilities of the token issued, when a UserID generated
	// in superGroup mode is used perform the login.
	AdditionalPolicies []string `json:"additional_policies" structs:"additional_policies" mapstructure:"additional_policies"`
}

// superGroupPaths creates the paths that are used to create UserIDs in superGroup mode
//
// Paths returned:
// supergroup/creds
// supergroup/creds-specific
func superGroupPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "supergroup/creds$",
			Fields: map[string]*framework.FieldSchema{
				"groups": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of Groups.",
				},
				"apps": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of Apps.",
				},
				"additional_policies": &framework.FieldSchema{
					Type:    framework.TypeString,
					Default: "",
					Description: `Comma separated list of policies for the Group. The UserID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this.
`,
				},
				"num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a UserID can access the Apps represented by the Group.",
				},
				"userid_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued UserID should expire.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathSuperGroupCredsUpdate,
			},
			HelpSynopsis:    pathSuperGroupCredsHelpSys,
			HelpDescription: pathSuperGroupCredsHelpDesc,
		},
		&framework.Path{
			Pattern: "supergroup/creds-specific$",
			Fields: map[string]*framework.FieldSchema{
				"user_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "UserID of the App.",
				},
				"groups": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Comma separated list of Groups.",
				},
				"apps": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Comma separated list of Apps.",
				},
				"additional_policies": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Comma separated list of policies for the Group. The UserID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this.
`,
				},
				"num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a UserID can access the Apps represented by the Group.",
				},
				"userid_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued UserID should expire.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathSuperGroupCredsSpecificUpdate,
			},
			HelpSynopsis:    pathSuperGroupCredsSpecificHelpSys,
			HelpDescription: pathSuperGroupCredsSpecificHelpDesc,
		},
	}
}

func (b *backend) setSuperGroupEntry(s logical.Storage, superGroupName string, superGroup *superGroupStorageEntry) error {
	b.superGroupLock.Lock()
	defer b.superGroupLock.Unlock()
	if entry, err := logical.StorageEntryJSON("supergroup/"+strings.ToLower(superGroupName), superGroup); err != nil {
		return err
	} else {
		return s.Put(entry)
	}
}

func (b *backend) deleteSuperGroupEntry(s logical.Storage, superGroupName string) error {
	if superGroupName == "" {
		return fmt.Errorf("missing superGroupName")
	}
	b.superGroupLock.Lock()
	defer b.superGroupLock.Unlock()

	return s.Delete("supergroup/" + strings.ToLower(superGroupName))
}

func (b *backend) superGroupEntry(s logical.Storage, superGroupName string) (*superGroupStorageEntry, error) {
	if superGroupName == "" {
		return nil, fmt.Errorf("missing superGroupName")
	}

	var result superGroupStorageEntry

	b.superGroupLock.RLock()
	defer b.superGroupLock.RUnlock()

	if entry, err := s.Get("supergroup/" + strings.ToLower(superGroupName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathSuperGroupCredsUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UserID:%s", err)
	}
	return b.handleSuperGroupCredsCommon(req, data, userID)
}

func (b *backend) pathSuperGroupCredsSpecificUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleSuperGroupCredsCommon(req, data, data.Get("user_id").(string))
}

func (b *backend) handleSuperGroupCredsCommon(req *logical.Request, data *framework.FieldData, userID string) (*logical.Response, error) {
	superGroup := &superGroupStorageEntry{
		Groups:             strutil.ParseStrings(data.Get("groups").(string)),
		Apps:               strutil.ParseStrings(data.Get("apps").(string)),
		AdditionalPolicies: policyutil.ParsePolicies(data.Get("additional_policies").(string)),
		NumUses:            data.Get("num_uses").(int),
		UserIDTTL:          time.Second * time.Duration(data.Get("userid_ttl").(int)),
		TokenTTL:           time.Second * time.Duration(data.Get("token_ttl").(int)),
		TokenMaxTTL:        time.Second * time.Duration(data.Get("token_max_ttl").(int)),
	}

	if len(superGroup.Groups) == 0 && len(superGroup.Apps) == 0 {
		return logical.ErrorResponse("missing groups and/or apps"), nil
	}

	if superGroup.NumUses < 0 {
		return logical.ErrorResponse("num_uses cannot be negative"), nil
	}

	if superGroup.TokenMaxTTL > time.Duration(0) && superGroup.TokenTTL > superGroup.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	if userID == "" {
		return logical.ErrorResponse("missing user_id"), nil
	}

	superGroupName := b.salt.SaltID(userID)

	// Store the entry.
	if err := b.setSuperGroupEntry(req.Storage, superGroupName, superGroup); err != nil {
		return nil, err
	}

	if err := b.registerUserIDEntry(req.Storage, selectorTypeSuperGroup, superGroupName, userID, &userIDStorageEntry{
		NumUses:   superGroup.NumUses,
		UserIDTTL: superGroup.UserIDTTL,
	}); err != nil {
		return nil, fmt.Errorf("failed to store user ID: %s", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"user_id":  userID,
			"selector": selectorTypeSuperGroup,
		},
	}, nil
}

const pathSuperGroupCredsSpecificHelpSys = `Assign a UserID of choice against any combination of
registered App(s) and/or Group(s), with custom options.`

const pathSuperGroupCredsSpecificHelpDesc = `This option is not recommended unless there is a specific
need to do so. This will assign a client supplied UserID to be used to
access all the specified Apps and all the participating Apps of all the
specified Groups. The options on this endpoint will supercede all the
options set on App(s)/Group(s). The UserIDs generated will expire after
a period defined by the 'userid_ttl' option and/or the backend mount's
maximum TTL value.`

const pathSuperGroupCredsHelpSys = `Generate UserID against any combination of registered App(s)
and/or Group(s), with custom options.`

const pathSuperGroupCredsHelpDesc = `The UserID generated using this endpoint will be able to
access all the specified Apps and all the participating Apps of all the
specified Groups. The options specified on this endpoint will supercede
all the options set on App(s)/Group(s). The UserIDs generated will expire
after a period defined by the 'userid_ttl' option and/or the backend
mount's maximum TTL value.`
