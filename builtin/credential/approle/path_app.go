package approle

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// appStorageEntry stores all the options that are set on an App
type appStorageEntry struct {
	// UUID that uniquely represents this App. This serves as a credential
	// to perform login using this App.
	SelectorID string `json:"selector_id" structs:"selector_id" mapstructure:"selector_id"`

	// UUID that serves as the HMAC key for the hashing the 'secret_id's
	// of the App
	HMACKey string `json:"hmac_key" structs:"hmac_key" mapstructure:"hmac_key"`

	// Policies that are to be required by the token to access this App
	Policies []string `json:"policies" structs:"policies" mapstructure:"policies"`

	// Number of times the SecretID generated against this App can be
	// used to perform login operation
	SecretIDNumUses int `json:"secret_id_num_uses" structs:"secret_id_num_uses" mapstructure:"secret_id_num_uses"`

	// Duration (less than the backend mount's max TTL) after which a
	// SecretID generated against the App will expire
	SecretIDTTL time.Duration `json:"secret_id_ttl" structs:"secret_id_ttl" mapstructure:"secret_id_ttl"`

	// Duration before which an issued token must be renewed
	TokenTTL time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`

	// Duration after which an issued token should not be allowed to be renewed
	TokenMaxTTL time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`

	// A constraint, if set, requires 'secret_id' credential to be presented during login
	BindSecretID bool `json:"bind_secret_id" structs:"bind_secret_id" mapstructure:"bind_secret_id"`

	// A constraint, if set, specifies the CIDR blocks from which logins should be allowed
	BindCIDRList string `json:"bind_cidr_list" structs:"bind_cidr_list" mapstructure:"bind_cidr_list"`

	// Period, if set, indicates that the token generated using this App
	// should never expire. The token should be renewed within the duration
	// specified by this value. The renewal duration will be fixed if the
	// value is not modified on the App. If the `Period` in the App is modified,
	// a token will pick up the new value during its next renewal.
	Period time.Duration `json:"period" mapstructure:"period" structs:"period"`
}

// appPaths creates all the paths that are used to register and manage an App.
//
// Paths returned:
// app/ - For listing all the registered Apps
// app/<app_name> - For registering an App
// app/<app_name>/policies - For updating the param
// app/<app_name>/secret-id-num-uses - For updating the param
// app/<app_name>/secret-id-ttl - For updating the param
// app/<app_name>/token-ttl - For updating the param
// app/<app_name>/token-max-ttl - For updating the param
// app/<app_name>/bind-secret-id - For updating the param
// app/<app_name>/period - For updating the param
// app/<app_name>/selector-id - For fetching the selector_id of an App
// app/<app_name>/secret-id - For issuing a secret_id against an App, also to list the secret_id_accessorss
// app/<app_name>/secret-id/<secret_id_accessor> - For reading the properties of, or deleting a secret_id
// app/<app_name>/custom-secret-id - For assigning a custom SecretID against an App
func appPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "app/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathAppList,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-list"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-list"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name"),
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"bind_secret_id": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Impose secret_id to be presented when logging in using this App. Defaults to 'true'.",
				},
				"bind_cidr_list": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Comma separated list of CIDR blocks, if set, specifies blocks of IP
addresses which can perform the login operation`,
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "default",
					Description: "Comma separated list of policies on the App.",
				},
				"secret_id_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times a SecretID can access the App, after which the SecretID will expire.",
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
				"period": &framework.FieldSchema{
					Type:    framework.TypeDurationSecond,
					Default: 0,
					Description: `If set, indicates that the token generated using this App
should never expire. The token should be renewed within the
duration specified by this value. The renewal duration will
be fixed, if this value is not modified. If the Period in the
App is modified, the token will pick up the new value during
its next renewal.`,
				},
			},
			ExistenceCheck: b.pathAppExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathAppCreateUpdate,
				logical.UpdateOperation: b.pathAppCreateUpdate,
				logical.ReadOperation:   b.pathAppRead,
				logical.DeleteOperation: b.pathAppDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/policies$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "default",
					Description: "Comma separated list of policies on the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppPoliciesUpdate,
				logical.ReadOperation:   b.pathAppPoliciesRead,
				logical.DeleteOperation: b.pathAppPoliciesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-policies"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-policies"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/bind-cidr-list$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"bind_cidr_list": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Comma separated list of CIDR blocks, if set, specifies blocks of IP
addresses which can perform the login operation`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppBindCIDRListUpdate,
				logical.ReadOperation:   b.pathAppBindCIDRListRead,
				logical.DeleteOperation: b.pathAppBindCIDRListDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-bind-cidr-list"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-bind-cidr-list"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/bind-secret-id$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"bind_secret_id": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     true,
					Description: "Impose secret_id to be presented when logging in using this App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppBindSecretIDUpdate,
				logical.ReadOperation:   b.pathAppBindSecretIDRead,
				logical.DeleteOperation: b.pathAppBindSecretIDDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-bind-secret-id"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-bind-secret-id"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/num-uses$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"secret_id_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times a SecretID can access the App, after which the SecretID will expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppSecretIDNumUsesUpdate,
				logical.ReadOperation:   b.pathAppSecretIDNumUsesRead,
				logical.DeleteOperation: b.pathAppSecretIDNumUsesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-num-uses"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-num-uses"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/secret-id-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"secret_id_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued SecretID should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppSecretIDTTLUpdate,
				logical.ReadOperation:   b.pathAppSecretIDTTLRead,
				logical.DeleteOperation: b.pathAppSecretIDTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-secret-id-ttl"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-secret-id-ttl"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/period$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"period": &framework.FieldSchema{
					Type:    framework.TypeDurationSecond,
					Default: 0,
					Description: `If set, indicates that the token generated using this App
should never expire. The token should be renewed within the
duration specified by this value. The renewal duration will
be fixed if this value is not modified. If the Period in the
App is modified, the token will pick up the new value during
its next renewal.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppPeriodUpdate,
				logical.ReadOperation:   b.pathAppPeriodRead,
				logical.DeleteOperation: b.pathAppPeriodDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-period"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-period"][1]),
		},

		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/token-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should expire.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppTokenTTLUpdate,
				logical.ReadOperation:   b.pathAppTokenTTLRead,
				logical.DeleteOperation: b.pathAppTokenTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-token-ttl"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-token-ttl"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/token-max-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: "Duration in seconds after which the issued token should not be allowed to be renewed.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppTokenMaxTTLUpdate,
				logical.ReadOperation:   b.pathAppTokenMaxTTLRead,
				logical.DeleteOperation: b.pathAppTokenMaxTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-token-max-ttl"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-token-max-ttl"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/selector-id$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathAppSelectorIDRead,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-selector-id"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-selector-id"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/secret-id/?$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"metadata": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Metadata that should be tied to the SecretID. This should be a JSON
formatted string containing the metadata in key value pairs.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppSecretIDUpdate,
				logical.ListOperation:   b.pathAppSecretIDList,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-secret-id"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-secret-id"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/secret-id/" + framework.GenericNameRegex("secret_id_accessor"),
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"secret_id_accessor": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Accessor of the SecretID",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathAppSecretIDAccessorRead,
				logical.DeleteOperation: b.pathAppSecretIDAccessorDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-secret-id-accessor"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-secret-id-accessor"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/custom-secret-id$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"secret_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "SecretID to be attached to the App.",
				},
				"metadata": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Metadata that should be tied to the SecretID. This should be a JSON
formatted string containing metadata in key value pairs.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathAppCustomSecretIDUpdate,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-custom-secret-id"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-custom-secret-id"][1]),
		},
	}
}

// pathAppExistenceCheck returns whether the app with the given name exists or not.
func (b *backend) pathAppExistenceCheck(req *logical.Request, data *framework.FieldData) (bool, error) {
	app, err := b.appEntry(req.Storage, data.Get("app_name").(string))
	if err != nil {
		return false, err
	}
	return app != nil, nil
}

// pathAppList is used to list all the Apps registered with the backend.
func (b *backend) pathAppList(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.appLock.RLock()
	defer b.appLock.RUnlock()
	apps, err := req.Storage.List("app/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(apps), nil
}

// pathAppSecretIDList is used to list all the 'secret_id_accessor's issued against the App.
func (b *backend) pathAppSecretIDList(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	// Get the app entry
	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return logical.ErrorResponse(fmt.Sprintf("app %s does not exist", appName)), nil
	}

	// If the argument to secretIDLock does not start with 2 hex
	// chars, a generic lock is returned. So, passing empty string
	// to get the "custom" lock that could be used for listing.
	lock := b.secretIDLock("")
	lock.RLock()
	defer lock.RUnlock()

	// Listing works one level at a time. Get the first level of data
	// which could then be used to get the actual SecretID storage entries.
	hashedSecretIDs, err := req.Storage.List(fmt.Sprintf("secret_id/%s/", b.salt.SaltID(app.SelectorID)))
	if err != nil {
		return nil, err
	}

	var listItems []string
	for _, hashedSecretID := range hashedSecretIDs {
		// Prepare the full index of the SecretIDs.
		entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(app.SelectorID), hashedSecretID)

		// SecretID locks are not indexed by SecretIDs itself.
		// This is because SecretIDs are not stored in plaintext
		// form anywhere in the backend, and hence accessing its
		// corresponding lock many times using SecretIDs is not
		// possible. Also, indexing it everywhere using hashedSecretIDs
		// makes listing operation easier.
		lock := b.secretIDLock(hashedSecretID)
		lock.RLock()

		result := secretIDStorageEntry{}
		if entry, err := req.Storage.Get(entryIndex); err != nil {
			lock.RUnlock()
			return nil, err
		} else if entry == nil {
			lock.RUnlock()
			return nil, fmt.Errorf("storage entry for SecretID is present but no content found at the index")
		} else if err := entry.DecodeJSON(&result); err != nil {
			lock.RUnlock()
			return nil, err
		}
		listItems = append(listItems, result.SecretIDAccessor)
		lock.RUnlock()
	}

	return logical.ListResponse(listItems), nil
}

// setAppEntry grabs a write lock and stores the options on an App into the storage.
// Also creates a reverse index from the App's SelectorID to the App itself.
func (b *backend) setAppEntry(s logical.Storage, appName string, app *appStorageEntry) error {
	b.appLock.Lock()
	defer b.appLock.Unlock()

	// Create a storage entry for the App
	entry, err := logical.StorageEntryJSON("app/"+strings.ToLower(appName), app)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for app %s", appName)
	}
	if err = s.Put(entry); err != nil {
		return err
	}

	// Create a storage entry for reverse mapping of SelectorID to App.
	// Note that secondary index is created when the appLock is held.
	return b.setSelectorIDEntry(s, app.SelectorID, &selectorIDStorageEntry{
		Type: "app",
		Name: appName,
	})
}

// appEntry grabs the read lock and fetches the options of an App from the storage
func (b *backend) appEntry(s logical.Storage, appName string) (*appStorageEntry, error) {
	if appName == "" {
		return nil, fmt.Errorf("missing app_name")
	}

	var result appStorageEntry

	b.appLock.RLock()
	defer b.appLock.RUnlock()

	if entry, err := s.Get("app/" + strings.ToLower(appName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// pathAppCreateUpdate registers a new App with the backend or updates the options
// of an existing App
func (b *backend) pathAppCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	// Check if the App already exists
	app, err := b.appEntry(req.Storage, appName)
	if err != nil {
		return nil, err
	}

	// Create a new entry object if this is a CreateOperation
	if app == nil && req.Operation == logical.CreateOperation {
		selectorID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to create selector_id: %s\n", err)
		}
		hmacKey, err := uuid.GenerateUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to create selector_id: %s\n", err)
		}
		app = &appStorageEntry{
			SelectorID: selectorID,
			HMACKey:    hmacKey,
		}
	} else {
		return nil, fmt.Errorf("App entry not found when the requested operation is to update it")
	}

	if bindSecretIDRaw, ok := data.GetOk("bind_secret_id"); ok {
		app.BindSecretID = bindSecretIDRaw.(bool)
	} else if req.Operation == logical.CreateOperation {
		app.BindSecretID = data.Get("bind_secret_id").(bool)
	}

	if bindCIDRListRaw, ok := data.GetOk("bind_cidr_list"); ok {
		app.BindCIDRList = strings.TrimSpace(bindCIDRListRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		app.BindCIDRList = data.Get("bind_cidr_list").(string)
	}
	if err = validateCIDRList(app.BindCIDRList); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to validate CIDR blocks: %s", err)), nil
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		app.Policies = policyutil.ParsePolicies(policiesRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		app.Policies = policyutil.ParsePolicies(data.Get("policies").(string))
	}

	periodRaw, ok := data.GetOk("period")
	if ok {
		app.Period = time.Second * time.Duration(periodRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		app.Period = time.Second * time.Duration(data.Get("period").(int))
	}
	if app.Period > b.System().MaxLeaseTTL() {
		return logical.ErrorResponse(fmt.Sprintf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", app.Period.String(), b.System().MaxLeaseTTL().String())), nil
	}

	if secretIDNumUsesRaw, ok := data.GetOk("secret_id_num_uses"); ok {
		app.SecretIDNumUses = secretIDNumUsesRaw.(int)
	} else if req.Operation == logical.CreateOperation {
		app.SecretIDNumUses = data.Get("secret_id_num_uses").(int)
	}
	if app.SecretIDNumUses < 0 {
		return logical.ErrorResponse("secret_id_num_uses cannot be negative"), nil
	}

	if secretIDTTLRaw, ok := data.GetOk("secret_id_ttl"); ok {
		app.SecretIDTTL = time.Second * time.Duration(secretIDTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		app.SecretIDTTL = time.Second * time.Duration(data.Get("secret_id_ttl").(int))
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		app.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		app.TokenTTL = time.Second * time.Duration(data.Get("token_ttl").(int))
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		app.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		app.TokenMaxTTL = time.Second * time.Duration(data.Get("token_max_ttl").(int))
	}

	// Check that the TokenTTL value provided is less than the TokenMaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if app.TokenMaxTTL > time.Duration(0) && app.TokenTTL > app.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	var resp *logical.Response
	if app.TokenMaxTTL > b.System().MaxLeaseTTL() {
		resp = &logical.Response{}
		resp.AddWarning("token_max_ttl is greater than the backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	// Store the entry.
	return resp, b.setAppEntry(req.Storage, appName, app)
}

// pathAppRead grabs a read lock and reads the options set on the App from the storage
func (b *backend) pathAppRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		// Convert the 'time.Duration' values to second.
		app.SecretIDTTL /= time.Second
		app.TokenTTL /= time.Second
		app.TokenMaxTTL /= time.Second
		app.Period /= time.Second

		// Create a map of data to be returned and remove sensitive information from it
		data := structs.New(app).Map()
		delete(data, "selector_id")
		delete(data, "hmac_key")

		return &logical.Response{
			Data: data,
		}, nil
	}
}

// pathAppDelete removes the App from the storage
func (b *backend) pathAppDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}

	// Acquire the lock before deleting the secrets.
	b.appLock.Lock()
	defer b.appLock.Unlock()

	// Just before the app is deleted, remove all the SecretIDs issued as part of the app.
	if err = b.flushSelectorSecrets(req.Storage, app.SelectorID); err != nil {
		return nil, fmt.Errorf("failed to invalidate the secrets belonging to app %s", appName)
	}

	// After deleting the SecretIDs, delete the App itself
	if err = req.Storage.Delete("app/" + strings.ToLower(appName)); err != nil {
		return nil, err
	}

	return nil, nil
}

// Returns the properties of the SecretID
func (b *backend) pathAppSecretIDAccessorRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	secretIDAccessor := data.Get("secret_id_accessor").(string)
	if secretIDAccessor == "" {
		return logical.ErrorResponse("missing secret_id_accessor"), nil
	}

	// SecretID is indexed based on salted SelectorID and HMACed SecretID.
	// Get the App details to fetch the SelectorID and accessor to get
	// the HMAC-ed SecretID.

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, fmt.Errorf("app %s does not exist", appName)
	}

	accessorEntry, err := b.secretIDAccessorEntry(req.Storage, secretIDAccessor)
	if err != nil {
		return nil, err
	}
	if accessorEntry == nil {
		return nil, fmt.Errorf("failed to find accessor entry for secret_id_accessor:%s\n", secretIDAccessor)
	}

	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(app.SelectorID), accessorEntry.HashedSecretID)

	lock := b.secretIDLock(accessorEntry.HashedSecretID)
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

func (b *backend) pathAppSecretIDAccessorDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	secretIDAccessor := data.Get("secret_id_accessor").(string)
	if secretIDAccessor == "" {
		return logical.ErrorResponse("missing secret_id_accessor"), nil
	}

	// SecretID is indexed based on salted SelectorID and HMACed SecretID.
	// Get the App details to fetch the SelectorID and accessor to get
	// the HMAC-ed SecretID.

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, fmt.Errorf("app %s does not exist", appName)
	}

	accessorEntry, err := b.secretIDAccessorEntry(req.Storage, secretIDAccessor)
	if err != nil {
		return nil, err
	}
	if accessorEntry == nil {
		return nil, fmt.Errorf("failed to find accessor entry for secret_id_accessor:%s\n", secretIDAccessor)
	}

	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(app.SelectorID), accessorEntry.HashedSecretID)

	lock := b.secretIDLock(accessorEntry.HashedSecretID)
	lock.Lock()
	defer lock.Unlock()

	return nil, req.Storage.Delete(entryIndex)
}

func (b *backend) pathAppBindCIDRListUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if bindCIDRListRaw, ok := data.GetOk("bind_cidr_list"); ok {
		app.BindCIDRList = strings.TrimSpace(bindCIDRListRaw.(string))
		if err = validateCIDRList(app.BindCIDRList); err != nil {
			return logical.ErrorResponse(fmt.Sprintf("failed to validate CIDR blocks: %s", err)), nil
		}
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing bind_cidr_list"), nil
	}
}

func (b *backend) pathAppBindCIDRListRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"bind_cidr_list": app.BindCIDRList,
			},
		}, nil
	}
}

func (b *backend) pathAppBindCIDRListDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	// Deleting a field implies setting the value to it's default value.
	app.BindCIDRList = data.GetDefaultOrZero("bind_cidr_list").(string)

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppBindSecretIDUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if bindSecretIDRaw, ok := data.GetOk("bind_secret_id"); ok {
		app.BindSecretID = bindSecretIDRaw.(bool)
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing bind_secret_id"), nil
	}
}

func (b *backend) pathAppBindSecretIDRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"bind_secret_id": app.BindSecretID,
			},
		}, nil
	}
}

func (b *backend) pathAppBindSecretIDDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	// Deleting a field implies setting the value to it's default value.
	app.BindSecretID = data.GetDefaultOrZero("bind_secret_id").(bool)

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppPoliciesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		app.Policies = policyutil.ParsePolicies(policiesRaw.(string))
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing policies"), nil
	}
}

func (b *backend) pathAppPoliciesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"policies": app.Policies,
			},
		}, nil
	}
}

func (b *backend) pathAppPoliciesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.Policies = policyutil.ParsePolicies(data.GetDefaultOrZero("policies").(string))

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppSecretIDNumUsesUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if numUsesRaw, ok := data.GetOk("secret_id_num_uses"); ok {
		app.SecretIDNumUses = numUsesRaw.(int)
		if app.SecretIDNumUses < 0 {
			return logical.ErrorResponse("secret_id_num_uses cannot be negative"), nil
		}
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing secret_id_num_uses"), nil
	}
}

func (b *backend) pathAppSelectorIDRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"selector_id": app.SelectorID,
			},
		}, nil
	}
}

func (b *backend) pathAppSecretIDNumUsesRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		return &logical.Response{
			Data: map[string]interface{}{
				"secret_id_num_uses": app.SecretIDNumUses,
			},
		}, nil
	}
}

func (b *backend) pathAppSecretIDNumUsesDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.SecretIDNumUses = data.GetDefaultOrZero("secret_id_num_uses").(int)

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppSecretIDTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if secretIDTTLRaw, ok := data.GetOk("secret_id_ttl"); ok {
		app.SecretIDTTL = time.Second * time.Duration(secretIDTTLRaw.(int))
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing secret_id_ttl"), nil
	}
}

func (b *backend) pathAppSecretIDTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.SecretIDTTL /= time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"secret_id_ttl": app.SecretIDTTL,
			},
		}, nil
	}
}

func (b *backend) pathAppSecretIDTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.SecretIDTTL = time.Second * time.Duration(data.GetDefaultOrZero("secret_id_ttl").(int))

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppPeriodUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if periodRaw, ok := data.GetOk("period"); ok {
		app.Period = time.Second * time.Duration(periodRaw.(int))
		if app.Period > b.System().MaxLeaseTTL() {
			return logical.ErrorResponse(fmt.Sprintf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", app.Period.String(), b.System().MaxLeaseTTL().String())), nil
		}
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing period"), nil
	}
}

func (b *backend) pathAppPeriodRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.Period /= time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"period": app.Period,
			},
		}, nil
	}
}

func (b *backend) pathAppPeriodDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.Period = time.Second * time.Duration(data.GetDefaultOrZero("period").(int))

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppTokenTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
		app.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
		if app.TokenMaxTTL > time.Duration(0) && app.TokenTTL > app.TokenMaxTTL {
			return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
		}
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing token_ttl"), nil
	}
}

func (b *backend) pathAppTokenTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.TokenTTL /= time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_ttl": app.TokenTTL,
			},
		}, nil
	}
}

func (b *backend) pathAppTokenTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.TokenTTL = time.Second * time.Duration(data.GetDefaultOrZero("token_ttl").(int))

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppTokenMaxTTLUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
		app.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
		if app.TokenMaxTTL > time.Duration(0) && app.TokenTTL > app.TokenMaxTTL {
			return logical.ErrorResponse("token_max_ttl should be greater than or equal to token_ttl"), nil
		}
		return nil, b.setAppEntry(req.Storage, appName, app)
	} else {
		return logical.ErrorResponse("missing token_max_ttl"), nil
	}
}

func (b *backend) pathAppTokenMaxTTLRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if app, err := b.appEntry(req.Storage, strings.ToLower(appName)); err != nil {
		return nil, err
	} else if app == nil {
		return nil, nil
	} else {
		app.TokenMaxTTL /= time.Second
		return &logical.Response{
			Data: map[string]interface{}{
				"token_max_ttl": app.TokenMaxTTL,
			},
		}, nil
	}
}

func (b *backend) pathAppTokenMaxTTLDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, nil
	}

	app.TokenMaxTTL = time.Second * time.Duration(data.GetDefaultOrZero("token_max_ttl").(int))

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppSecretIDUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	secretID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SecretID:%s", err)
	}
	return b.handleAppSecretIDCommon(req, data, secretID)
}

func (b *backend) pathAppCustomSecretIDUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.handleAppSecretIDCommon(req, data, data.Get("secret_id").(string))
}

func (b *backend) handleAppSecretIDCommon(req *logical.Request, data *framework.FieldData, secretID string) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	if secretID == "" {
		return logical.ErrorResponse("missing secret_id"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return logical.ErrorResponse(fmt.Sprintf("app %s does not exist", appName)), nil
	}

	// Currently, only one type of bind is implemented.
	// Ensure that it is enabled.
	if !app.BindSecretID {
		return logical.ErrorResponse("bind_secret_id is not set on the app"), nil
	}

	secretIDStorage := &secretIDStorageEntry{
		SecretIDNumUses: app.SecretIDNumUses,
		SecretIDTTL:     app.SecretIDTTL,
	}

	metadata := data.Get("metadata").(string)
	if metadata != "" {
		json.Unmarshal([]byte(metadata), &secretIDStorage.Metadata)
		for key, value := range secretIDStorage.Metadata {
			if key != "" && value == "" {
				return logical.ErrorResponse(fmt.Sprintf("metadata should only contain <key,value> inputs as JSON; invalid value for key '%s'", key)), nil
			}
		}
	}

	if secretIDStorage, err = b.registerSecretIDEntry(req.Storage, app.SelectorID, secretID, app.HMACKey, secretIDStorage); err != nil {
		return nil, fmt.Errorf("failed to store SecretID: %s", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"secret_id":          secretID,
			"secret_id_accessor": secretIDStorage.SecretIDAccessor,
		},
	}, nil
}

// Checks if all the CIDR blocks in the comma separated list are valid by parsing it.
func validateCIDRList(cidrList string) error {
	if cidrList == "" {
		return nil
	}

	cidrBlocks := strings.Split(cidrList, ",")
	for _, block := range cidrBlocks {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(block)); err != nil {
			return err
		}
	}
	return nil
}

var appHelp = map[string][2]string{
	"app-list": {
		"Lists all the Apps registered with the backend.",
		"The list will contain the names of the Apps.",
	},
	"app": {
		"Register an App with the backend.",
		`An App can represent a service, a machine or anything that can be IDed.
The set of policies on the App defines access to the App, meaning, any
Vault token with a policy set that is a superset of the policies on the
App registered here will have access to the App. If a SecretID is desired
to be generated against only this specific App, it can be done via
'app/<app_name>/secret-id' and 'app/<app_name>/custom-secret-id' endpoints.
The properties of the SecretID created against the App and the properties
of the token issued with the SecretID generated againt the App, can be
configured using the parameters of this endpoint.`,
	},
	"app-bind-secret-id": {
		"Impose secret_id to be presented during login using this App.",
		`By setting this to 'true', during login the parameter 'secret_id' becomes a mandatory argument.
The value of 'secret_id' can be retrieved using 'app/<app_name>/secret-id' endpoint.`,
	},
	"app-bind-cidr-list": {
		`Comma separated list of CIDR blocks, if set, specifies blocks of IP
addresses which can perform the login operation`,
		`During login, the IP address of the client will be checked to see if it
belongs to the CIDR blocks specified. If CIDR blocks were set and if the
IP is not encompassed by it, login fails`,
	},
	"app-policies": {
		"Policies of the App.",
		`A comma-delimited set of Vault policies that defines access to the App.
All the Vault tokens with policies that encompass the policy set
defined on the App, can access the App.`,
	},
	"app-num-uses": {
		"Use limit of the SecretID generated against the App.",
		`If the SecretIDs are generated/assigned against the App using the
'app/<app_name>/secret-id' or 'app/<app_name>/custom-secret-id' endpoints,
then the number of times that SecretID can access the App is defined by
this option.`,
	},
	"app-secret-id-ttl": {
		`Duration in seconds, representing the lifetime of the SecretIDs
that are generated against the App using 'app/<app_name>/secret-id' or
'app/<app_name>/custom-secret-id' endpoints.`,
		``,
	},
	"app-secret-id-accessor": {
		"Read or delete a issued secret_id",
		`This is particularly useful to clean-up the non-expiring 'secret_id's.
The list operation on the 'app/<app_name>/secret-id' endpoint will return
the 'secret_id_accessor's. This endpoint can be used to read the properties
of the secret. If the 'secret_id_num_uses' field in the response is 0, it
represents a non-expiring 'secret_id'. This endpoint can be invoked to delete
the 'secret_id's as well.`,
	},
	"app-token-ttl": {
		`Duration in seconds, the lifetime of the token issued by using the SecretID that
is generated against this App, before which the token needs to be renewed.`,
		`If SecretIDs are generated against the App, using 'app/<app_name>/secret-id' or the
'app/<app_name>/custom-secret-id' endpoints, and if those SecretIDs are used
to perform the login operation, then the value of 'token-ttl' defines the
lifetime of the token issued, before which the token needs to be renewed.`,
	},
	"app-token-max-ttl": {
		`Duration in seconds, the maximum lifetime of the tokens issued by using
the SecretIDs that were generated against this App, after which the
tokens are not allowed to be renewed.`,
		`If SecretIDs are generated against the App using 'app/<app_name>/secret-id'
or the 'app/<app_name>/custom-secret-id' endpoints, and if those SecretIDs
are used to perform the login operation, then the value of 'token-max-ttl'
defines the maximum lifetime of the tokens issued, after which the tokens
cannot be renewed. A reauthentication is required after this duration.
This value will be capped by the backend mount's maximum TTL value.`,
	},
	"app-selector-id": {
		"Returns the 'selector_id' of the App.",
		`If login is performed from an App, then its 'selector_id' should be presented
as a credential during the login. This 'selector_id' can be retrieved using
this endpoint.`,
	},
	"app-secret-id": {
		"Generate a SecretID against this App.",
		`The SecretID generated using this endpoint will be scoped to access
just this App and none else. The properties of this SecretID will be
based on the options set on the App. It will expire after a period
defined by the 'secret_id_ttl' option on the App and/or the backend
mount's maximum TTL value.`,
	},
	"app-custom-secret-id": {
		"Assign a SecretID of choice against the App.",
		`This option is not recommended unless there is a specific need
to do so. This will assign a client supplied SecretID to be used to access
the App. This SecretID will behave similarly to the SecretIDs generated by
the backend. The properties of this SecretID will be based on the options
set on the App. It will expire after a period defined by the 'secret_id_ttl'
option on the App and/or the backend mount's maximum TTL value.`,
	},
	"app-period": {
		"Updates the value of 'period' on the App",
		`If set,  indicates that the token generated using this App
should never expire. The token should be renewed within the
duration specified by this value. The renewal duration will
be fixed. If the Period in the App is modified, the token
will pick up the new value during its next renewal.`,
	},
}
