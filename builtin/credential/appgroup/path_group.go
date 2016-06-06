package appgroup

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// groupStorageEntry stores all the options that are set on a Group
type groupStorageEntry struct {
	// UUID that uniquely represents this Group
	SelectorID string `json:"selector_id" structs:"selector_id" mapstructure:"selector_id"`

	// UUID that serves as the HMAC key for the hashing the 'secret_id's of the App
	HMACKey string `json:"hmac_key" structs:"hmac_key" mapstructure:"hmac_key"`

	// All the participating Apps of the Group
	Apps []string `json:"apps" structs:"apps" mapstructure:"apps"`

	// Number of times the SecretID generated against the Group can be used to perform login
	SecretIDNumUses int `json:"secret_id_num_uses" structs:"secret_id_num_uses" mapstructure:"secret_id_num_uses"`

	// Duration (less than the backend mount's max TTL) after which a SecretID generated against the Group will expire
	SecretIDTTL time.Duration `json:"secret_id_ttl" structs:"secret_id_ttl" mapstructure:"secret_id_ttl"`

	// Duration before which an issued token must be renewed
	TokenTTL time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`

	// Duration after which an issued token should not be allowed to be renewed
	TokenMaxTTL time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`

	// A constraint to require 'secret_id' credential during login
	BindSecretID bool `json:"bind_secret_id" structs:"bind_secret_id" mapstructure:"bind_secret_id"`

	// Along with the combined set of Apps' policies, the policies in this list will be
	// added to capabilities of the token issued, when a SecretID generated against a Group
	// is used perform the login.
	AdditionalPolicies []string `json:"additional_policies" structs:"additional_policies" mapstructure:"additional_policies"`
}

// groupPaths creates all the paths that are used to register and manage an Group.
//
// Paths returned:
// group/
// group/<group_name>
// group/<group_name>/policies
// group/<group_name>/bind-secret-id
// group/<group_name>/num-uses
// group/<group_name>/secret_id-ttl
// group/<group_name>/token-ttl
// group/<group_name>/token-max-ttl
// group/<group_name>/selector-id
// group/<group_name>/secret-id
// group/<group_name>/custom-secret-id
func groupPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "group/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathGroupList,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-list"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-list"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name"),
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"apps": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of Apps belonging to the group",
				},
				"bind_secret_id": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Impose secret_id to be presented during login using this Group. Defaults to 'true'.",
				},
				"additional_policies": &framework.FieldSchema{
					Type:    framework.TypeString,
					Default: "",
					Description: `Comma separated list of policies for the Group. The SecretID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this.
`,
				},
				"secret_id_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a SecretID can access the Apps represented by the Group.",
				},
				"secret_id_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued SecretID should expire.",
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
				logical.CreateOperation: b.pathGroupCreateUpdate,
				logical.UpdateOperation: b.pathGroupCreateUpdate,
				logical.ReadOperation:   b.pathGroupRead,
				logical.DeleteOperation: b.pathGroupDelete,
			},
			ExistenceCheck:  b.pathGroupExistenceCheck,
			HelpSynopsis:    strings.TrimSpace(groupHelp["group"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/apps$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"apps": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "Comma separated list of Apps belonging to the group",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupAppsUpdate,
				logical.ReadOperation:   b.pathGroupAppsRead,
				logical.DeleteOperation: b.pathGroupAppsDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-apps"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-apps"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/bind-secret-id$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"bind_secret_id": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Description: "Impose secret_id to be presented during login using this Group.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupBindSecretIDUpdate,
				logical.ReadOperation:   b.pathGroupBindSecretIDRead,
				logical.DeleteOperation: b.pathGroupBindSecretIDDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-bind-secret-id"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-bind-secret-id"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/additional-policies$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"additional_policies": &framework.FieldSchema{
					Type:    framework.TypeString,
					Default: "",
					Description: `Comma separated list of policies for the Group. The SecretID created against the Group,
will have access to the union of all the policies of the Apps. In
addition to those, a set of policies can be assigned using this.
`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupAdditionalPoliciesUpdate,
				logical.ReadOperation:   b.pathGroupAdditionalPoliciesRead,
				logical.DeleteOperation: b.pathGroupAdditionalPoliciesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-additional-policies"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-additional-policies"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/num-uses$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"secret_id_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a SecretID can access the Apps represented by the Group.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupSecretIDNumUsesUpdate,
				logical.ReadOperation:   b.pathGroupSecretIDNumUsesRead,
				logical.DeleteOperation: b.pathGroupSecretIDNumUsesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-num-uses"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-num-uses"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/secret_id-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"secret_id_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued SecretID should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupSecretIDTTLUpdate,
				logical.ReadOperation:   b.pathGroupSecretIDTTLRead,
				logical.DeleteOperation: b.pathGroupSecretIDTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-secret_id-ttl"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-secret_id-ttl"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/token-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupTokenTTLUpdate,
				logical.ReadOperation:   b.pathGroupTokenTTLRead,
				logical.DeleteOperation: b.pathGroupTokenTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-token-ttl"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-token-ttl"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/token-max-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupTokenMaxTTLUpdate,
				logical.ReadOperation:   b.pathGroupTokenMaxTTLRead,
				logical.DeleteOperation: b.pathGroupTokenMaxTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-token-max-ttl"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-token-max-ttl"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/selector-id$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathGroupSelectorIDRead,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-selector-id"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-selector-id"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/secret-id/?$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathGroupSecretIDRead,
				logical.ListOperation: b.pathGroupSecretIDList,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-secret-id"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-secret-id"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/secret-id/" + framework.GenericNameRegex("secret_id_hmac"),
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"secret_id_hmac": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "HMAC of the secret ID",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathGroupSecretIDHMACRead,
				logical.DeleteOperation: b.pathGroupSecretIDHMACDelete,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-secret-id"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-secret-id"][1]),
		},
		&framework.Path{
			Pattern: "group/" + framework.GenericNameRegex("group_name") + "/custom-secret-id$",
			Fields: map[string]*framework.FieldSchema{
				"group_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the Group.",
				},
				"secret_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "",
					Description: "SecretID to be attached to the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathGroupCustomSecretIDUpdate,
			},
			HelpSynopsis:    strings.TrimSpace(groupHelp["group-custom-secret-id"][0]),
			HelpDescription: strings.TrimSpace(groupHelp["group-custom-secret-id"][1]),
		},
	}
}

// pathGroupExistenceCheck returns if the group with the given name exists or not.
func (b *backend) pathGroupExistenceCheck(req *logical.Request, data *framework.FieldData) (bool, error) {
	group, err := b.groupEntry(req.Storage, data.Get("group_name").(string))
	if err != nil {
		return false, err
	}
	return group != nil, nil
}

// pathGroupList is used to list all the Groups registered with the backend.
func (b *backend) pathGroupList(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.groupLock.RLock()
	defer b.groupLock.RUnlock()

	groups, err := req.Storage.List("group/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(groups), nil
}

// pathGroupSecretIDList is used to list all the Apps registered with the backend.
func (b *backend) pathGroupSecretIDList(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return logical.ErrorResponse(fmt.Sprintf("group %s does not exist", groupName)), nil
	}

	// Get the "custom" lock
	lock := b.secretIDLock("")
	lock.RLock()
	defer lock.RUnlock()

	secrets, err := req.Storage.List(fmt.Sprintf("secret_id/%s/", b.salt.SaltID(group.SelectorID)))
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(secrets), nil
}

// setAppEntry grabs a write lock and stores the options on a Group into the storage
func (b *backend) setGroupEntry(s logical.Storage, groupName string, group *groupStorageEntry) error {
	b.groupLock.Lock()
	defer b.groupLock.Unlock()

	entry, err := logical.StorageEntryJSON("group/"+strings.ToLower(groupName), group)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for group %s", groupName)
	}
	if err = s.Put(entry); err != nil {
		return err
	}

	return b.setSelectorIDEntry(s, group.SelectorID, &selectorIDStorageEntry{
		Type: selectorTypeGroup,
		Name: groupName,
	})
}

// groupEntry grabs the read lock and fetches the options of an Group from the storage
func (b *backend) groupEntry(s logical.Storage, groupName string) (*groupStorageEntry, error) {
	if groupName == "" {
		return nil, fmt.Errorf("missing group_name")
	}

	var result groupStorageEntry

	b.groupLock.RLock()
	defer b.groupLock.RUnlock()

	if entry, err := s.Get("group/" + strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// pathAppCreateUpdate registers a new Group with the backend or updates the options
// of an existing Group
func (b *backend) pathGroupCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, groupName)
	if err != nil {
		return nil, err
	}
	if group == nil {
		selectorID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to create selector_id: %s\n", err)
		}
		hmacKey, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to create selector_id: %s\n", err)
		}
		group = &groupStorageEntry{
			SelectorID: selectorID,
			HMACKey:    hmacKey,
		}
	}

	if appsRaw, ok := data.GetOk("apps"); ok {
		group.Apps = strutil.RemoveDuplicates(strings.Split(appsRaw.(string), ","))
	} else if req.Operation == logical.CreateOperation {
		group.Apps = strutil.RemoveDuplicates(strings.Split(data.Get("apps").(string), ","))
	}

	if bindSecretIDRaw, ok := data.GetOk("bind_secret_id"); ok {
		group.BindSecretID = bindSecretIDRaw.(bool)
	} else if req.Operation == logical.CreateOperation {
		group.BindSecretID = data.Get("bind_secret_id").(bool)
	}

	if additionalPoliciesRaw, ok := data.GetOk("additional_policies"); ok {
		group.AdditionalPolicies = policyutil.ParsePolicies(additionalPoliciesRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		group.AdditionalPolicies = policyutil.ParsePolicies(data.Get("additional_policies").(string))
	}

	if numUsesRaw, ok := data.GetOk("secret_id_num_uses"); ok {
		group.SecretIDNumUses = numUsesRaw.(int)
	} else if req.Operation == logical.CreateOperation {
		group.SecretIDNumUses = data.Get("secret_id_num_uses").(int)
	}

	if group.SecretIDNumUses < 0 {
		return logical.ErrorResponse("secret_id_num_uses cannot be negative"), nil
	}

	if secretIDTTLRaw, ok := data.GetOk("secret_id_ttl"); ok {
		group.SecretIDTTL = time.Second * time.Duration(secretIDTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		group.SecretIDTTL = time.Second * time.Duration(data.Get("secret_id_ttl").(int))
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		group.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		group.TokenTTL = time.Second * time.Duration(data.Get("token_ttl").(int))
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		group.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		group.TokenMaxTTL = time.Second * time.Duration(data.Get("token_max_ttl").(int))
	}

	if group.TokenMaxTTL > time.Duration(0) && group.TokenTTL > group.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	// Store the entry.
	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

// pathGroupRead grabs a read lock and reads the options set on the Group from the storage
func (b *backend) pathGroupRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		// Convert the values to second
		group.SecretIDTTL = group.SecretIDTTL / time.Second
		group.TokenTTL = group.TokenTTL / time.Second
		group.TokenMaxTTL = group.TokenMaxTTL / time.Second

		// Create a map of data to be returned and remove sensitive information from it
		data := structs.New(group).Map()
		delete(data, "selector_id")
		delete(data, "hmac_key")

		return &logical.Response{
			Data: data,
		}, nil
	}
}

// pathGroupDelete removes the Group from the storage
func (b *backend) pathGroupDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}
	b.groupLock.Lock()
	defer b.groupLock.Unlock()

	if err := req.Storage.Delete("group/" + strings.ToLower(groupName)); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathGroupAppsUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if appsRaw, ok := data.GetOk("apps"); ok {
		group.Apps = strings.Split(appsRaw.(string), ",")
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing apps"), nil
	}
}

func (b *backend) pathGroupAppsRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"apps": group.Apps,
			},
		}, nil
	}
}

func (b *backend) pathGroupAppsDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.Apps = (&groupStorageEntry{}).Apps

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupBindSecretIDUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if bindSecretIDRaw, ok := data.GetOk("bind_secret_id"); ok {
		group.BindSecretID = bindSecretIDRaw.(bool)
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing bind_secret_id"), nil
	}
}

func (b *backend) pathGroupSecretIDHMACRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	hashedSecretID := data.Get("secret_id_hmac").(string)
	if hashedSecretID == "" {
		return logical.ErrorResponse("missing secret_id_hmac"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, fmt.Errorf("group %s does not exist", groupName)
	}

	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(group.SelectorID), hashedSecretID)

	lock := b.secretIDLock(hashedSecretID)
	lock.RLock()
	defer lock.RUnlock()

	result := secretIDStorageEntry{}
	if entry, err := req.Storage.Get(entryIndex); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: structs.New(result).Map(),
	}, nil
}

func (b *backend) pathGroupSecretIDHMACDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	hashedSecretID := data.Get("secret_id_hmac").(string)
	if hashedSecretID == "" {
		return logical.ErrorResponse("missing secret_id_hmac"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, fmt.Errorf("group %s does not exist", groupName)
	}

	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(group.SelectorID), hashedSecretID)

	lock := b.secretIDLock(hashedSecretID)
	lock.Lock()
	defer lock.Unlock()

	return nil, req.Storage.Delete(entryIndex)
}

func (b *backend) pathGroupBindSecretIDRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"bind_secret_id": group.BindSecretID,
			},
		}, nil
	}
}

func (b *backend) pathGroupBindSecretIDDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.BindSecretID = (&groupStorageEntry{}).BindSecretID

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupAdditionalPoliciesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if additionalPoliciesRaw, ok := data.GetOk("additional_policies"); ok {
		group.AdditionalPolicies = policyutil.ParsePolicies(additionalPoliciesRaw.(string))
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing additional_policies"), nil
	}
}

func (b *backend) pathGroupAdditionalPoliciesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"additional_policies": group.AdditionalPolicies,
			},
		}, nil
	}
}

func (b *backend) pathGroupAdditionalPoliciesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.AdditionalPolicies = (&groupStorageEntry{}).AdditionalPolicies

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupSecretIDNumUsesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if numUsesRaw, ok := data.GetOk("secret_id_num_uses"); ok {
		group.SecretIDNumUses = numUsesRaw.(int)
		if group.SecretIDNumUses < 0 {
			return logical.ErrorResponse("secret_id_num_uses cannot be negative"), nil
		}
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing secret_id_num_uses"), nil
	}
}

func (b *backend) pathGroupSelectorIDRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"selector_id": group.SelectorID,
			},
		}, nil
	}
}

func (b *backend) pathGroupSecretIDNumUsesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"secret_id_num_uses": group.SecretIDNumUses,
			},
		}, nil
	}
}

func (b *backend) pathGroupSecretIDNumUsesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.SecretIDNumUses = (&groupStorageEntry{}).SecretIDNumUses

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupSecretIDTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if secretIDTTLRaw, ok := data.GetOk("secret_id_ttl"); ok {
		group.SecretIDTTL = time.Second * time.Duration(secretIDTTLRaw.(int))
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing secret_id_ttl"), nil
	}
}

func (b *backend) pathGroupSecretIDTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		group.SecretIDTTL = group.SecretIDTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"secret_id_ttl": group.SecretIDTTL,
			},
		}, nil
	}
}

func (b *backend) pathGroupSecretIDTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.SecretIDTTL = (&groupStorageEntry{}).SecretIDTTL

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupTokenTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		group.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
		if group.TokenMaxTTL > time.Duration(0) && group.TokenTTL > group.TokenMaxTTL {
			return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
		}
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing token_ttl"), nil
	}
}

func (b *backend) pathGroupTokenTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		group.TokenTTL = group.TokenTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_ttl": group.TokenTTL,
			},
		}, nil
	}
}

func (b *backend) pathGroupTokenTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.TokenTTL = (&groupStorageEntry{}).TokenTTL

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupTokenMaxTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		group.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
		if group.TokenMaxTTL > time.Duration(0) && group.TokenTTL > group.TokenMaxTTL {
			return logical.ErrorResponse("token_max_ttl should be greater than token_ttl"), nil
		}
		return nil, b.setGroupEntry(req.Storage, groupName, group)
	} else {
		return logical.ErrorResponse("missing token_max_ttl"), nil
	}
}

func (b *backend) pathGroupTokenMaxTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if group, err := b.groupEntry(req.Storage, strings.ToLower(groupName)); err != nil {
		return nil, err
	} else if group == nil {
		return nil, nil
	} else {
		group.TokenMaxTTL = group.TokenMaxTTL / time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_max_ttl": group.TokenMaxTTL,
			},
		}, nil
	}
}

func (b *backend) pathGroupTokenMaxTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, nil
	}

	group.TokenMaxTTL = (&groupStorageEntry{}).TokenMaxTTL

	return nil, b.setGroupEntry(req.Storage, groupName, group)
}

func (b *backend) pathGroupSecretIDRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SecretID:%s", err)
	}
	return b.handleGroupSecretIDCommon(req, data, secretID)
}

func (b *backend) pathGroupCustomSecretIDUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleGroupSecretIDCommon(req, data, data.Get("secret_id").(string))
}

func (b *backend) handleGroupSecretIDCommon(req *logical.Request, data *framework.FieldData, secretID string) (*logical.Response, error) {
	groupName := data.Get("group_name").(string)
	if groupName == "" {
		return logical.ErrorResponse("missing group_name"), nil
	}

	if secretID == "" {
		return logical.ErrorResponse("missing secret_id"), nil
	}

	group, err := b.groupEntry(req.Storage, strings.ToLower(groupName))
	if err != nil {
		return nil, err
	}
	if group == nil {
		return logical.ErrorResponse(fmt.Sprintf("Group %s does not exist", groupName)), nil
	}

	if !group.BindSecretID {
		return logical.ErrorResponse("bind_secret_id is not set on the group"), nil
	}

	if err = b.registerSecretIDEntry(req.Storage, group.SelectorID, secretID, group.HMACKey, &secretIDStorageEntry{
		SecretIDNumUses: group.SecretIDNumUses,
		SecretIDTTL:     group.SecretIDTTL,
	}); err != nil {
		return nil, fmt.Errorf("failed to store secret ID: %s", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"secret_id": secretID,
		},
	}, nil
}

var groupHelp = map[string][2]string{
	"group-list": {
		"Lists all the Groups registered with the backend.",
		"The list will contain the names of the Groups.",
	},
	"group": {
		"Create a group of Apps and define custom options on it.",
		`A group registered with the backend represents a group of Apps. The options
set on the group supercedes the options set on the participating Apps.
Ther no single set of policies that are to be applied on the group.
The policies are dynamically determined during the login period. The
effective polices on the group is a union of all the policies of all
the participating Apps. However, a comma-delimited set of 'additional_policies'
can be supplied on the group. These policies will be appended to the
effective policies.`,
	},
	"group-apps": {
		"Comma-delimited list of participating Apps of the group.",
		`All the Apps listed here should be registered with the backend before the
login operation is performed. `,
	},
	"group-bind-secret-id": {
		"Impose secret_id to be presented during login using this Group.",
		`By setting this to 'true', during login the parameter 'secret_id' becomes a mandatory argument.
The value of 'secret_id' can be retrieved using 'group/<group_name>/secret-id' endpoint.`,
	},
	"group-additional-policies": {
		`Additional policies to be assigned to the tokens issued by using the SecretIDs
that were generated against this group.`,
		`If a SecretID is generated/assigned against this group, and if these SecretIDs
are used to perform a login operation, the tokens issued will have a
combined set of policies from each participating App. In addition,
the 'additional_policies' defined using this option will be appended
to the issued token's effective policies.`,
	},
	"group-num-uses": {
		"Use limit of the SecretID generated against the group.",
		`If the SecretIDs are generated/assigned against the group using
'group/<group_name>/secret-id' or 'group/<group_name>/custom-secret-id'
endpoints, then the number of times that these SecretIDs can access
the participating Apps is defined by this option.`,
	},
	"group-secret_id-ttl": {
		`Duration in seconds, representing the lifetime of the SecretIDs
that are generated against the Group using 'group/<group_name>/secret-id'
or 'group/<group_name>/custom-secret-id' endpoints.`,
		`If the SecretIDs are generated against the Group using 'group/<group_name>/secret-id'
or 'group/<group_name>/custom-secret-id' endpoints, then those SecretIDs
will expire after the duration specified by this option. Note that this
value will be capped by the backend mount's maximux TTL value.`,
	},
	`group-token-ttl`: {
		`Duration in seconds, the lifetime of the token issued by using
the SecretID that is generated against this Group, before which the token
needs to be renewed.`,
		`If SecretIDs are generated against the Group, using 'group/<group_name>/secret-id'
or the 'group/<group_name>/custom-secret-id' endpoints, and if those SecretIDs
are used to perform the login operation, then the value of 'token-ttl'
defines the lifetime of the token issued, before which teh token needs
to be renewed.`,
	},
	"group-token-max-ttl": {
		`Duration in seconds, the maximux lifetime of the tokens issued by using the SecretID that were generated against the Group, after which the tokens are not allowed to be renewed.`,
		`If SecretIDs are generated against the Group using 'group/<group_name>/secret-id'
or the 'group/<group_name>/custom-secret-id' endpoints, and if those SecretIDs
are used to perform the login operation, then the value of 'token-max-ttl'
defines the maximum lifetime of the tokens issued, after which the tokens
cannot be renewed. A reauthentication is required after this duration.
This value will be capped by the backend mount's maximux TTL value.`,
	},
	"group-selector-id": {
		"Returns the 'selector_id' of the Group.",
		`If login is performed from a Group, then its 'selector_id' should be presented
as a credential during the login. This 'selector_id' can be retrieved using
this endpoint.`,
	},
	"group-secret-id": {
		"Generate a SecretID against this Group.",
		`The SecretID generated using this endpoint will be scoped to access
the participant Apps of this Group. The properties of this SecretID will
be based on the options set on the Group. It will expire after a period
defined by the 'secret_id_ttl' option on the Group and/or the backend mount's
maximum TTL value.`,
	},
	"group-custom-secret-id": {
		"Assign a SecretID of choice against the Group.",
		`This option is not recommended unless there is a specific need
to do so. This will assign a client supplied SecretID to be used to access
the participating Apps of the Group. This SecretID will behavie similarly
to the SecretIDs generated by the backend. The properties of this SecretID
will be based on the options set on the Group. It will expire after a
period defined by the 'secret_id_ttl' option on the Group and/or the backend
mount's maximux TTL value.`,
	},
}
