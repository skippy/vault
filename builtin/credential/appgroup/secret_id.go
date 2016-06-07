package appgroup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	selectorTypeApp        = "app"
	selectorTypeGroup      = "group"
	selectorTypeSuperGroup = "supergroup"
)

// secretIDStorageEntry represents the information stored in storage when a SecretID is created.
// The structure of the SecretID storage entry is the same for all the types of SecretIDs generated.
type secretIDStorageEntry struct {
	// Number of times this SecretID can be used to perform the login operation
	SecretIDNumUses int `json:"secret_id_num_uses" structs:"secret_id_num_uses" mapstructure:"secret_id_num_uses"`

	// Duration after which this SecretID should expire. This is capped by the backend mount's
	// max TTL value.
	SecretIDTTL time.Duration `json:"secret_id_ttl" structs:"secret_id_ttl" mapstructure:"secret_id_ttl"`

	// The time in UTC when the SecretID was created
	CreationTime time.Time `json:"creation_time" structs:"creation_time" mapstructure:"creation_time"`

	// The time in UTC when the SecretID becomes eligible for tidy operation.
	// Tidying is performed by the PeriodicFunc of the backend which is 1 minute apart.
	ExpirationTime time.Time `json:"expiration_time" structs:"expiration_time" mapstructure:"expiration_time"`

	// The time in UTC representing the last time this storage entry was modified
	LastUpdatedTime time.Time `json:"last_updated_time" structs:"last_updated_time" mapstructure:"last_updated_time"`
}

// validationResponse will be the result of credentials verification performed during login.
// This contains information that either needs to be returned to the client or information
// required to be stored as metadata in the response, and/or the information required to
// create the client token.
type validationResponse struct {
	SelectorID   string        `json:"selector_id" structs:"selector_id" mapstructure:"selector_id"`
	HMACKey      string        `json:"hmac_key" structs:"hmac_key" mapstructure:"hmac_key"`
	TokenTTL     time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`
	TokenMaxTTL  time.Duration `json:"token_max_ttl" structs:"token_max_ttl" mapstructure:"token_max_ttl"`
	Policies     []string      `json:"policies" structs:"policies" mapstructure:"policies"`
	BindSecretID bool          `json:"bind_secret_id" structs:"bind_secret_id" mapstructure:"bind_secret_id"`
}

// selectorStorageEntry represents the reverse mapping from the selector
// to the respective app or group that the selectorID belongs to.
type selectorIDStorageEntry struct {
	// Type of selector: "app", "group", "supergroup"
	Type string `json:"type" structs:"type" mapstructure:"type"`

	// Name of the app, group or supergroup, depending on the type
	Name string `json:"name" structs:"name" mapstructure:"name"`
}

// setSelectorIDEntry creates a storage entry that maps the selector ID
// to an App or a Group.
func (b *backend) setSelectorIDEntry(s logical.Storage, selectorID string, selectorEntry *selectorIDStorageEntry) error {
	lock := b.selectorIDLock(selectorID)
	lock.Lock()
	defer lock.Unlock()

	entry, err := logical.StorageEntryJSON("selector/"+selectorID, selectorEntry)
	if err != nil {
		return err
	}
	if err = s.Put(entry); err != nil {
		return err
	}
	return nil
}

// selectorIDEntry is used to read the storage entry that maps the selector
// ID to an App or a Group.
func (b *backend) selectorIDEntry(s logical.Storage, selectorID string) (*selectorIDStorageEntry, error) {
	if selectorID == "" {
		return nil, fmt.Errorf("missing selectorID")
	}

	lock := b.selectorIDLock(selectorID)
	lock.RLock()
	defer lock.RUnlock()

	var result selectorIDStorageEntry

	if entry, err := s.Get("selector/" + selectorID); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Identifies the supplied selector ID and validates it, checks if the supplied
// secret ID has a corresponding entry in the backend and udpates the use count
// if needed.
func (b *backend) validateCredentials(s logical.Storage, data *framework.FieldData) (*validationResponse, error) {
	// SelectorID must be supplied during every login
	selectorID := strings.TrimSpace(data.Get("selector_id").(string))
	if selectorID == "" {
		return nil, fmt.Errorf("missing selector_id")
	}

	// First validate the selector ID. Based on which type the selector
	// belongs to, the validationResp will contain all the information
	// required to continue the credential verification. Based on which
	// binds are set, continue the verification process.
	validationResp, err := b.validateSelectorID(s, selectorID)
	if err != nil {
		return nil, err
	}
	if validationResp == nil {
		return nil, fmt.Errorf("failed to validate selector_id")
	}

	// If 'bind_secret_id' was set on app/group/supergroup, look for the
	// field 'secret_id' to be specified and validate it.
	if validationResp.BindSecretID {
		secretID := strings.TrimSpace(data.Get("secret_id").(string))
		if secretID == "" {
			return nil, fmt.Errorf("missing secret_id")
		}

		// Check if the secret ID supplied is valid. If use limit was specified
		// on the secret ID, it will be decremented in this call.
		valid, err := b.validateBindSecretID(s, selectorID, secretID, validationResp.HMACKey)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("invalid secret_id: %s\n", secretID)
		}
	} else {
		return nil, fmt.Errorf("failed to find the binding creteria; there should be at least one")
	}

	// As and when more binds are supported, add additional verification process

	return validationResp, nil
}

// validateSelectorID checks if there is a storage entry that maps the selector ID
// to app/group/supergroup. If it finds a mapping, then a validation response is
// returned containing a generic set of information that is used to perform further
// verification of credentials supplied and the information required to authenticate
// the request.
func (b *backend) validateSelectorID(s logical.Storage, selectorID string) (*validationResponse, error) {
	// Look for the storage entry that maps the selectorID to app/group/supergroup.
	selector, err := b.selectorIDEntry(s, selectorID)
	if err != nil {
		return nil, err
	}
	if selector == nil {
		return nil, fmt.Errorf("failed to find selector for selector_id:%s\n", selectorID)
	}

	resp := &validationResponse{}

	switch selector.Type {
	case selectorTypeApp:
		// Get the properties of App and populate the response
		app, err := b.appEntry(s, selector.Name)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("app %s referred by the secret ID does not exist", selector.Name)
		}
		resp.Policies = app.Policies
		resp.TokenTTL = app.TokenTTL
		resp.TokenMaxTTL = app.TokenMaxTTL
		resp.SelectorID = app.SelectorID
		resp.HMACKey = app.HMACKey
		resp.BindSecretID = app.BindSecretID
	case selectorTypeGroup:
		// Get the properties of Group and populate the response
		group, err := b.groupEntry(s, selector.Name)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, fmt.Errorf("group %s referred by the secret ID does not exist", selector.Name)
		}
		groupPolicies, err := b.fetchPolicies(s, group.Apps)
		if err != nil {
			return nil, err
		}
		// Append the union of all the policies from all the apps on the group
		resp.Policies = append(resp.Policies, groupPolicies...)

		// Append the additional policies set on the group
		resp.Policies = append(resp.Policies, group.AdditionalPolicies...)

		resp.TokenTTL = group.TokenTTL
		resp.TokenMaxTTL = group.TokenMaxTTL
		resp.SelectorID = group.SelectorID
		resp.HMACKey = group.HMACKey
		resp.BindSecretID = group.BindSecretID
	case selectorTypeSuperGroup:
		// Get the properties of supergroup and populate the response
		superGroup, err := b.superGroupEntry(s, selector.Name)
		if err != nil {
			return nil, err
		}
		if superGroup == nil {
			return nil, fmt.Errorf("supergroup credential referred by the secret ID does not exist")
		}
		// Get the properties of each group within supergroup.
		for _, groupName := range superGroup.Groups {
			group, err := b.groupEntry(s, groupName)
			if err != nil {
				return nil, err
			}
			groupPolicies, err := b.fetchPolicies(s, group.Apps)
			if err != nil {
				return nil, err
			}
			// Append the union of all the policies from all the apps on the group
			resp.Policies = append(resp.Policies, groupPolicies...)
			// Append the additional policies set on the group
			resp.Policies = append(resp.Policies, group.AdditionalPolicies...)
		}

		// Get the properties of each app within supergroup.
		for _, appName := range superGroup.Apps {
			app, err := b.appEntry(s, appName)
			if err != nil {
				return nil, err
			}
			// Append the policies set on the app
			resp.Policies = append(resp.Policies, app.Policies...)
		}

		// Append the additonal policies set on the supergroup entry
		resp.Policies = append(resp.Policies, superGroup.AdditionalPolicies...)

		resp.TokenTTL = superGroup.TokenTTL
		resp.TokenMaxTTL = superGroup.TokenMaxTTL
		resp.SelectorID = superGroup.SelectorID
		resp.HMACKey = superGroup.HMACKey
		resp.BindSecretID = superGroup.BindSecretID
	default:
		return nil, fmt.Errorf("unknown selector type")
	}

	// Cap the token_ttl and token_max_ttl values.
	resp.TokenTTL, resp.TokenMaxTTL, err = b.SanitizeTTL(resp.TokenTTL, resp.TokenMaxTTL)
	if err != nil {
		return nil, err
	}

	// The policies in response will have duplicates. Clean it up, and add 'default'
	// policy if not added already.
	resp.Policies = policyutil.SanitizePolicies(resp.Policies, true)

	return resp, nil
}

// validateBindSecretID is used to determine if the given secret ID is a valid one.
// The SecretID is looked to be present only under the sub-view of the selector.
// This ensures that the SecretIDs that are reused between selector types, the
// correct one is referred to. If the SecretIDs are always generated by the
// backend, then there will be no collision between the SecretIDs from different
// types. But, if 'custom_secret_id's are assigned across different selector types,
// then it should be supported.
func (b *backend) validateBindSecretID(s logical.Storage, selectorID, secretID, hmacKey string) (bool, error) {
	hashedSecretID, err := createHMAC(hmacKey, secretID)
	if err != nil {
		return false, fmt.Errorf("failed to create HMAC of secret_id: %s", err)
	}
	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(selectorID), hashedSecretID)

	// SecretID locks are always index based on hashedSecretIDs. This helps
	// acquiring the locks when the secret IDs are listed. This allows grabbing
	// the correct locks even if the secret IDs are not known in plaintext.
	lock := b.secretIDLock(hashedSecretID)
	lock.RLock()

	result := secretIDStorageEntry{}
	if entry, err := s.Get(entryIndex); err != nil {
		lock.RUnlock()
		return false, err
	} else if entry == nil {
		lock.RUnlock()
		return false, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		lock.RUnlock()
		return false, err
	}

	// SecretIDNumUses will be zero only if the usage limit was not set at all,
	// in which case, the SecretID will remain to be valid as long as it is not
	// expired.
	if result.SecretIDNumUses == 0 {
		lock.RUnlock()
		return true, nil
	}

	// If the SecretIDNumUses is non-zero, it means that its use-count should be updated
	// in the storage. Switch the lock from a `read` to a `write` and update
	// the storage entry.
	lock.RUnlock()

	lock.Lock()
	defer lock.Unlock()

	// Lock switching may change the data. Refresh the contents.
	result = secretIDStorageEntry{}
	if entry, err := s.Get(entryIndex); err != nil {
		return false, err
	} else if entry == nil {
		return false, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return false, err
	}

	// If there exists a single use left, delete the SecretID entry from
	// the storage but do not fail the validation request. Subsequest
	// requests to use the same SecretID will fail.
	if result.SecretIDNumUses == 1 {
		if err := s.Delete(entryIndex); err != nil {
			return false, err
		}

		// The storage entry for superGroup type is not created by any endpoints
		// and it is not cleaned up in any other way. When the SecretID belonging
		// to the superGroup storage entry is getting invalidated, the entry should
		// be deleted as well.
		selector, err := b.selectorIDEntry(s, selectorID)
		if err != nil {
			return false, err
		}
		if selector == nil {
			return false, fmt.Errorf("failed to find selector for selector_id:%s\n", selectorID)
		}
		if selector.Type == selectorTypeSuperGroup {
			if err := b.deleteSuperGroupEntry(s, selector.Name); err != nil {
				return false, err
			}
		}
	} else {
		// If the use count is greater than one, decrement it and update the last updated time.
		result.SecretIDNumUses -= 1
		result.LastUpdatedTime = time.Now().UTC()
		if entry, err := logical.StorageEntryJSON(entryIndex, &result); err != nil {
			return false, fmt.Errorf("failed to decrement the use count for secret ID:%s", secretID)
		} else if err = s.Put(entry); err != nil {
			return false, fmt.Errorf("failed to decrement the use count for secret ID:%s", secretID)
		}
	}

	return true, nil
}

// selectorIDLock is used to get a lock from the pre-initialized map
// of locks. Map is indexed based on the first 2 characters of the
// selectorID, which is a random UUID. If the input is not hex encoded
// or if it is empty a "custom" lock will be returned.
func (b *backend) selectorIDLock(selectorID string) *sync.RWMutex {
	var lock *sync.RWMutex
	var ok bool
	if len(selectorID) >= 2 {
		lock, ok = b.selectorIDLocksMap[selectorID[0:2]]
	}
	if !ok || lock == nil {
		// Fall back for custom secret IDs
		lock = b.selectorIDLocksMap["custom"]
	}
	return lock
}

// secretIDLock is used to get a lock from the pre-initialized map
// of locks. Map is indexed based on the first 2 characters of the
// hashed secretID. If the input is not hex encoded or if empty, a
// "custom" lock will be returned.
func (b *backend) secretIDLock(hashedSecretID string) *sync.RWMutex {
	var lock *sync.RWMutex
	var ok bool
	if len(hashedSecretID) >= 2 {
		lock, ok = b.secretIDLocksMap[hashedSecretID[0:2]]
	}
	if !ok || lock == nil {
		// Fall back for custom secret IDs
		lock = b.secretIDLocksMap["custom"]
	}
	return lock
}

// Creates a SHA256 HMAC of the given 'value' using the given 'key'
// and returns a hex encoded string.
func createHMAC(key, value string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("invalid HMAC key")
	}
	hm := hmac.New(sha256.New, []byte(key))
	hm.Write([]byte(value))
	return hex.EncodeToString(hm.Sum(nil)), nil
}

// registerSecretIDEntry creates a new storage entry for the given SecretID.
func (b *backend) registerSecretIDEntry(s logical.Storage, selectorID, secretID, hmacKey string, secretEntry *secretIDStorageEntry) error {
	hashedSecretID, err := createHMAC(hmacKey, secretID)
	if err != nil {
		return fmt.Errorf("failed to create HMAC of secret_id: %s", err)
	}
	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(selectorID), hashedSecretID)

	lock := b.secretIDLock(hashedSecretID)
	lock.RLock()

	entry, err := s.Get(entryIndex)
	if err != nil {
		lock.RUnlock()
		return err
	}
	if entry != nil {
		lock.RUnlock()
		return fmt.Errorf("secret ID is already registered")
	}

	// If there isn't an entry for the secretID already, switch the read lock
	// with a write lock and create an entry.
	lock.RUnlock()
	lock.Lock()
	defer lock.Unlock()

	// But before saving a new entry, check if the secretID entry was created during the lock switch.
	entry, err = s.Get(entryIndex)
	if err != nil {
		return err
	}
	if entry != nil {
		return fmt.Errorf("secret ID is already registered")
	}

	// Create a new entry for the SecretID

	// Set the creation time for the SecretID
	currentTime := time.Now().UTC()
	secretEntry.CreationTime = currentTime
	secretEntry.LastUpdatedTime = currentTime

	// If SecretIDTTL is not specified or if it crosses the backend mount's limit,
	// cap the expiration to backend's max. Otherwise, use it to determine the
	// expiration time.
	if secretEntry.SecretIDTTL < time.Duration(0) || secretEntry.SecretIDTTL > b.System().MaxLeaseTTL() {
		secretEntry.ExpirationTime = currentTime.Add(b.System().MaxLeaseTTL())
	} else if secretEntry.SecretIDTTL != time.Duration(0) {
		// Set the ExpirationTime only if SecretIDTTL was set. SecretIDs should not
		// expire by default.
		secretEntry.ExpirationTime = currentTime.Add(secretEntry.SecretIDTTL)
	}

	if entry, err := logical.StorageEntryJSON(entryIndex, secretEntry); err != nil {
		return err
	} else if err = s.Put(entry); err != nil {
		return err
	}

	return nil
}

// Iterates through all the Apps, fetches the polices from each App
// and returns a union of all the policies combined together. An error
// is thrown if any App in the list of Apps supplied is non-existent
// with the backend.
func (b *backend) fetchPolicies(s logical.Storage, apps []string) ([]string, error) {
	var policies []string
	for _, appName := range apps {
		app, err := b.appEntry(s, appName)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, fmt.Errorf("app %s does not exist", appName)
		}
		// Append the policies of each App into a collection
		policies = append(policies, app.Policies...)
	}
	return strutil.RemoveDuplicates(policies), nil
}

// flushSelectorSecrets deletes all the 'secret_id's that belong to the given
// selector ID.
func (b *backend) flushSelectorSecrets(s logical.Storage, selectorID string) error {
	// Acquire the custom lock to perform listing of 'secret_id's
	lock := b.secretIDLock("")
	lock.RLock()
	hashedSecretIDs, err := s.List(fmt.Sprintf("secret_id/%s/", b.salt.SaltID(selectorID)))
	if err != nil {
		return err
	}
	lock.RUnlock()
	for _, hashedSecretID := range hashedSecretIDs {
		// Acquire the lock belonging to the secret ID
		lock = b.secretIDLock(hashedSecretID)
		lock.Lock()
		entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(selectorID), hashedSecretID)
		if err := s.Delete(entryIndex); err != nil {
			lock.Unlock()
			return fmt.Errorf("error deleting secret ID %s from storage: %s", hashedSecretID, err)
		}
		lock.Unlock()
	}
	return nil
}
