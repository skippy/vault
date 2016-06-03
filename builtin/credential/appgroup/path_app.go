package appgroup

import (
	"fmt"
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
	// UUID that uniquely represents this App
	SelectorID string `json:"selector_id" structs:"selector_id" mapstructure:"selector_id"`

	// UUID that serves as the HMAC key for the hashing the 'secret_id's of the App
	HMACKey string `json:"hmac_key" structs:"hmac_key" mapstructure:"hmac_key"`

	// Policies that are to be required by the token to access the App
	Policies []string `json:"policies" structs:"policies" mapstructure:"policies"`

	// Number of times the SecretID generated against the App can be used to perform login
	SecretIDNumUses int `json:"secret_id_num_uses" structs:"secret_id_num_uses" mapstructure:"secret_id_num_uses"`

	// Duration (less than the backend mount's max TTL) after which a SecretID generated against the App will expire
	SecretIDTTL time.Duration `json:"secret_id_ttl" structs:"secret_id_ttl" mapstructure:"secret_id_ttl"`

	// Duration before which an issued token must be renewed
	TokenTTL time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`

	// Duration after which an issued token should not be allowed to be renewed
	TokenMaxTTL time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`

	// A constraint to require 'secret_id' credential during login
	BindSecretID bool `json:"bind_secret_id" structs:"bind_secret_id" mapstructure:"bind_secret_id"`
}

// appPaths creates all the paths that are used to register and manage an App.
//
// Paths returned:
// app/
// app/<app_name>
// app/<app_name>/policies
// app/<app_name>/num-uses
// app/<app_name>/secret-id-ttl
// app/<app_name>/token-ttl
// app/<app_name>/token-max-ttl
// app/<app_name>/bind-secret-id
// app/<app_name>/selector-id
// app/<app_name>/secret-id
// app/<app_name>/custom-secret-id
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
					Description: "Impose secret_id to be presented during login using this App. Defaults to 'true'.",
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "default",
					Description: "Comma separated list of policies on the App.",
				},
				"secret_id_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "Number of times the a SecretID can access the App, after which it will expire.",
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
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/bind-secret-id$",
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"bind_secret_id": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Description: "Impose secret_id to be presented during login using this App.",
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
					Description: "Number of times the a SecretID can access the App, after which it will expire.",
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
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathAppSecretIDRead,
				logical.ListOperation: b.pathAppSecretIDList,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-secret-id"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-secret-id"][1]),
		},
		&framework.Path{
			Pattern: "app/" + framework.GenericNameRegex("app_name") + "/secret-id/" + framework.GenericNameRegex("secret_id_hmac"),
			Fields: map[string]*framework.FieldSchema{
				"app_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the App.",
				},
				"secret_id_hmac": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "HMAC of the secret ID",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathAppSecretIDHMACRead,
				logical.DeleteOperation: b.pathAppSecretIDHMACDelete,
			},
			HelpSynopsis:    strings.TrimSpace(appHelp["app-secret-id-hmac"][0]),
			HelpDescription: strings.TrimSpace(appHelp["app-secret-id-hmac"][1]),
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
					Default:     "",
					Description: "SecretID to be attached to the App.",
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

// pathAppExistenceCheck returns if the app with the given name exists or not.
func (b *backend) pathAppExistenceCheck(req *logical.Request, data *framework.FieldData) (bool, error) {
	app, err := b.appEntry(req.Storage, data.Get("app_name").(string))
	if err != nil {
		return false, err
	}
	return app != nil, nil
}

// pathAppList is used to list all the Apps registered with the backend.
func (b *backend) pathAppList(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.appLock.RLock()
	defer b.appLock.RUnlock()

	apps, err := req.Storage.List("app/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(apps), nil
}

// pathAppSecretIDList is used to list all the Apps registered with the backend.
func (b *backend) pathAppSecretIDList(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return logical.ErrorResponse(fmt.Sprintf("app %s does not exist", appName)), nil
	}

	// Get the "custom" lock
	lock := b.secretIDLock("")
	lock.RLock()
	defer lock.RUnlock()

	secrets, err := req.Storage.List(fmt.Sprintf("secret_id/%s/", b.salt.SaltID(app.SelectorID)))
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(secrets), nil
}

// setAppEntry grabs a write lock and stores the options on an App into the storage
func (b *backend) setAppEntry(s logical.Storage, appName string, app *appStorageEntry) error {
	b.appLock.Lock()
	defer b.appLock.Unlock()

	entry, err := logical.StorageEntryJSON("app/"+strings.ToLower(appName), app)
	if err != nil {
		return err
	}
	if err = s.Put(entry); err != nil {
		return err
	}

	return b.setSelectorIDEntry(s, app.SelectorID, &selectorIDStorageEntry{
		Type: selectorTypeApp,
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

	// Fetch or create an entry for the app
	app, err := b.appEntry(req.Storage, appName)
	if err != nil {
		return nil, err
	}
	// Create a new entry object if this is a CreateOperation
	if app == nil {
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
	}

	if bindSecretIDRaw, ok := data.GetOk("bind_secret_id"); ok {
		app.BindSecretID = bindSecretIDRaw.(bool)
	} else if req.Operation == logical.CreateOperation {
		app.BindSecretID = data.Get("bind_secret_id").(bool)
	}

	if policiesRaw, ok := data.GetOk("policies"); ok {
		app.Policies = policyutil.ParsePolicies(policiesRaw.(string))
	} else if req.Operation == logical.CreateOperation {
		app.Policies = policyutil.ParsePolicies(data.Get("policies").(string))
	}

	if numUsesRaw, ok := data.GetOk("secret_id_num_uses"); ok {
		app.SecretIDNumUses = numUsesRaw.(int)
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

	resp := &logical.Response{}

	// Check that the TokenMaxTTL value provided is less than the TokenMaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if app.TokenMaxTTL > time.Duration(0) && app.TokenTTL > app.TokenMaxTTL {
		return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
	}

	if app.TokenMaxTTL > b.System().MaxLeaseTTL() {
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
		app.SecretIDTTL = app.SecretIDTTL / time.Second
		app.TokenTTL = app.TokenTTL / time.Second
		app.TokenMaxTTL = app.TokenMaxTTL / time.Second

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
	b.appLock.Lock()
	defer b.appLock.Unlock()

	if err := req.Storage.Delete("app/" + strings.ToLower(appName)); err != nil {
		return nil, err
	}

	return nil, nil
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

func (b *backend) pathAppSecretIDHMACRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	hashedSecretID := data.Get("secret_id_hmac").(string)
	if hashedSecretID == "" {
		return logical.ErrorResponse("missing secret_id_hmac"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, fmt.Errorf("app %s does not exist", appName)
	}

	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(app.SelectorID), hashedSecretID)

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

	respData := structs.New(result).Map()
	return &logical.Response{
		Data: respData,
	}, nil
}

func (b *backend) pathAppSecretIDHMACDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	appName := data.Get("app_name").(string)
	if appName == "" {
		return logical.ErrorResponse("missing app_name"), nil
	}

	hashedSecretID := data.Get("secret_id_hmac").(string)
	if hashedSecretID == "" {
		return logical.ErrorResponse("missing secret_id_hmac"), nil
	}

	app, err := b.appEntry(req.Storage, strings.ToLower(appName))
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, fmt.Errorf("app %s does not exist", appName)
	}

	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(app.SelectorID), hashedSecretID)

	lock := b.secretIDLock(hashedSecretID)
	lock.Lock()
	defer lock.Unlock()

	return nil, req.Storage.Delete(entryIndex)
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

	// Deleting a field means resetting the value in the entry.
	app.BindSecretID = (&appStorageEntry{}).BindSecretID

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

	// Deleting a field means resetting the value in the entry.
	app.Policies = (&appStorageEntry{}).Policies

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

	// Deleting a field means resetting the value in the entry.
	app.SecretIDNumUses = (&appStorageEntry{}).SecretIDNumUses

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
		app.SecretIDTTL = app.SecretIDTTL / time.Second
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

	// Deleting a field means resetting the value in the entry.
	app.SecretIDTTL = (&appStorageEntry{}).SecretIDTTL

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
		app.TokenTTL = app.TokenTTL / time.Second
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

	// Deleting a field means resetting the value in the entry.
	app.TokenTTL = (&appStorageEntry{}).TokenTTL

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
		app.TokenMaxTTL = app.TokenMaxTTL / time.Second
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

	// Deleting a field means resetting the value in the entry.
	app.TokenMaxTTL = (&appStorageEntry{}).TokenMaxTTL

	return nil, b.setAppEntry(req.Storage, appName, app)
}

func (b *backend) pathAppSecretIDRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	if !app.BindSecretID {
		return logical.ErrorResponse("bind_secret_id is not set on the app"), nil
	}

	if err = b.registerSecretIDEntry(req.Storage, app.SelectorID, secretID, app.HMACKey, &secretIDStorageEntry{
		SecretIDNumUses: app.SecretIDNumUses,
		SecretIDTTL:     app.SecretIDTTL,
	}); err != nil {
		return nil, fmt.Errorf("failed to store secret ID: %s", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"secret_id": secretID,
		},
	}, nil
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
	"app-secret-id-hmac": {
		"Read or delete a issued secret_id",
		`This is particularly useful to clean-up the non-expiring 'secret_id's.
The list operation on the 'app/<app_name>/secret-id' endpoint will return
the HMACed 'secret_id's. This endpoint can be used to read the properties
of the secret. If the 'secret_idnum_uses' field in the response is 0, it represents
a non-expiring 'secret_id'. The same endpoint can be invoked again to delete
it.`,
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
}
