package approle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// secretIDStorageEntry represents the information stored in storage
// when a SecretID is created. The structure of the SecretID storage
// entry is the same for all the types of SecretIDs generated.
type secretIDStorageEntry struct {
	// Accessor for the SecretID. It is a random UUID serving as
	// a secondary index for the SecretID. This uniquely identifies
	// the SecretID it belongs to, and hence can be used for listing
	// and deleting SecretIDs. Accessors cannot be used as valid
	// selectors during login.
	SecretIDAccessor string `json:"secret_id_accessor" structs:"secret_id_accessor" mapstructure:"secret_id_accessor"`

	// Number of times this SecretID can be used to perform the login operation
	SecretIDNumUses int `json:"secret_id_num_uses" structs:"secret_id_num_uses" mapstructure:"secret_id_num_uses"`

	// Duration after which this SecretID should expire. This is
	// capped by the backend mount's max TTL value.
	SecretIDTTL time.Duration `json:"secret_id_ttl" structs:"secret_id_ttl" mapstructure:"secret_id_ttl"`

	// The time in UTC when the SecretID was created
	CreationTime time.Time `json:"creation_time" structs:"creation_time" mapstructure:"creation_time"`

	// The time in UTC when the SecretID becomes eligible for tidy
	// operation. Tidying is performed by the PeriodicFunc of the
	// backend which is 1 minute apart.
	ExpirationTime time.Time `json:"expiration_time" structs:"expiration_time" mapstructure:"expiration_time"`

	// The time in UTC representing the last time this storage entry was modified
	LastUpdatedTime time.Time `json:"last_updated_time" structs:"last_updated_time" mapstructure:"last_updated_time"`

	// Metadata that belongs to the SecretID.
	Metadata map[string]string `json:"metadata" structs:"metadata" mapstructure:"metadata"`
}

// Represents the payload of the storage entry of the accessor that maps to a unique
// SecretID. Note that SecretIDs should never be stored in plaintext anywhere in the
// backend. HashedSecretID will be used as an index to fetch the properties of the
// SecretID and to delete the SecretID.
type secretIDAccessorStorageEntry struct {
	// Hash of the SecretID which can be used to find the storage index at which
	// properties of SecretID is stored.
	HashedSecretID string `json:"hashed_secret_id" structs:"hashed_secret_id" mapstructure:"hashed_secret_id"`
}

// selectorStorageEntry represents the reverse mapping from SelectorID to App
type selectorIDStorageEntry struct {
	// Type of selector: "app"
	Type string `json:"type" structs:"type" mapstructure:"type"`

	// Name of the app
	Name string `json:"name" structs:"name" mapstructure:"name"`
}

// setSelectorIDEntry creates a storage entry that maps SelectorID to App
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

// selectorIDEntry is used to read the storage entry that maps SelectorID to App
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

// Checks if the App represented by the SelectorID still exists
func (b *backend) validateSelectorID(s logical.Storage, selectorID string) (*appStorageEntry, error) {
	// Look for the storage entry that maps the selectorID to app
	selector, err := b.selectorIDEntry(s, selectorID)
	if err != nil {
		return nil, err
	}
	if selector == nil {
		return nil, fmt.Errorf("failed to find selector for selector_id:%s\n", selectorID)
	}

	app, err := b.appEntry(s, selector.Name)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, fmt.Errorf("app %s referred by the SecretID does not exist", selector.Name)
	}

	return app, nil
}

// Validates the supplied SelectorID and SecretID
func (b *backend) validateCredentials(req *logical.Request, data *framework.FieldData) (*appStorageEntry, error) {
	// SelectorID must be supplied during every login
	selectorID := strings.TrimSpace(data.Get("selector_id").(string))
	if selectorID == "" {
		return nil, fmt.Errorf("missing selector_id")
	}

	// Validate the SelectorID and get the App entry
	app, err := b.validateSelectorID(req.Storage, selectorID)
	if err != nil {
		return nil, err
	}

	// Calculate the TTL boundaries since this reflects the properties of the token issued
	if app.TokenTTL, app.TokenMaxTTL, err = b.SanitizeTTL(app.TokenTTL, app.TokenMaxTTL); err != nil {
		return nil, err
	}

	// Take actions based on the set bind options

	// If 'bind_cidr_list' was set, verify the CIDR restrictions
	// Keep the optional binding parameters outside of the switch
	// block below.
	if app.BindCIDRList != "" {
		cidrBlocks := strings.Split(app.BindCIDRList, ",")
		for _, block := range cidrBlocks {
			_, cidr, err := net.ParseCIDR(block)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr: %s", err)
			}

			var addr string
			if req.Connection != nil {
				addr = req.Connection.RemoteAddr
			}
			if addr == "" || !cidr.Contains(net.ParseIP(addr)) {
				return nil, fmt.Errorf("unauthorized source address")
			}
		}
	}

	switch {
	// If 'bind_secret_id' was set on app, look for the field 'secret_id'
	// to be specified and validate it.
	case app.BindSecretID:
		secretID := strings.TrimSpace(data.Get("secret_id").(string))
		if secretID == "" {
			return nil, fmt.Errorf("missing secret_id")
		}

		// Check if the SecretID supplied is valid. If use limit was specified
		// on the SecretID, it will be decremented in this call.
		valid, err := b.validateBindSecretID(req.Storage, selectorID, secretID, app.HMACKey)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("invalid secret_id: %s\n", secretID)
		}
	default:
		// Ensure at least one bind criterion is set.
		return nil, fmt.Errorf("failed to find the binding creteria; there should be at least one required bind parameter set")
	}

	// As and when more binds are supported, add additional verification process

	return app, nil
}

// validateBindSecretID is used to determine if the given SecretID is a valid one.
func (b *backend) validateBindSecretID(s logical.Storage, selectorID, secretID, hmacKey string) (bool, error) {
	hashedSecretID, err := createHMAC(hmacKey, secretID)
	if err != nil {
		return false, fmt.Errorf("failed to create HMAC of secret_id: %s", err)
	}
	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(selectorID), hashedSecretID)

	// SecretID locks are always index based on hashedSecretIDs. This helps
	// acquiring the locks when the SecretIDs are listed. This allows grabbing
	// the correct locks even if the SecretIDs are not known in plaintext.
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
	} else {
		// If the use count is greater than one, decrement it and update the last updated time.
		result.SecretIDNumUses -= 1
		result.LastUpdatedTime = time.Now().UTC()
		if entry, err := logical.StorageEntryJSON(entryIndex, &result); err != nil {
			return false, fmt.Errorf("failed to decrement the use count for SecretID:%s", secretID)
		} else if err = s.Put(entry); err != nil {
			return false, fmt.Errorf("failed to decrement the use count for SecretID:%s", secretID)
		}
	}

	return true, nil
}

// selectorIDLock is used to get a lock from the pre-initialized map
// of locks. Map is indexed based on the first 2 characters of the
// SelectorID, which is a random UUID. If the input is not hex encoded
// or if it is empty a "custom" lock will be returned.
func (b *backend) selectorIDLock(selectorID string) *sync.RWMutex {
	var lock *sync.RWMutex
	var ok bool
	if len(selectorID) >= 2 {
		lock, ok = b.selectorIDLocksMap[selectorID[0:2]]
	}
	if !ok || lock == nil {
		// Fall back for custom SecretIDs
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
		// Fall back for custom SecretIDs
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
func (b *backend) registerSecretIDEntry(s logical.Storage, selectorID, secretID, hmacKey string, secretEntry *secretIDStorageEntry) (*secretIDStorageEntry, error) {
	hashedSecretID, err := createHMAC(hmacKey, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC of secret_id: %s", err)
	}
	entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(selectorID), hashedSecretID)

	lock := b.secretIDLock(hashedSecretID)
	lock.RLock()

	entry, err := s.Get(entryIndex)
	if err != nil {
		lock.RUnlock()
		return nil, err
	}
	if entry != nil {
		lock.RUnlock()
		return nil, fmt.Errorf("SecretID is already registered")
	}

	// If there isn't an entry for the secretID already, switch the read lock
	// with a write lock and create an entry.
	lock.RUnlock()
	lock.Lock()
	defer lock.Unlock()

	// But before saving a new entry, check if the secretID entry was created during the lock switch.
	entry, err = s.Get(entryIndex)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		return nil, fmt.Errorf("SecretID is already registered")
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

	// Before storing the SecretID, store its accessor.
	if err := b.createAccessor(s, secretEntry, hashedSecretID); err != nil {
		return nil, err
	}

	if entry, err := logical.StorageEntryJSON(entryIndex, secretEntry); err != nil {
		return nil, err
	} else if err = s.Put(entry); err != nil {
		return nil, err
	}

	return secretEntry, nil
}

// selectorIDEntry is used to read the storage entry that maps the
// SelectorID to an App. This method should be called when the lock
// for the corresponding SecretID is held.
func (b *backend) secretIDAccessorEntry(s logical.Storage, secretIDAccessor string) (*secretIDAccessorStorageEntry, error) {
	if secretIDAccessor == "" {
		return nil, fmt.Errorf("missing secretIDAccessor")
	}

	var result secretIDAccessorStorageEntry

	// Create index entry, mapping the accessor to the token ID
	entryIndex := "accessor/" + b.salt.SaltID(secretIDAccessor)

	if entry, err := s.Get(entryIndex); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// createAccessor creates an identifier for the SecretID. A storage index,
// mapping the accessor to the SecretID is also created. This method should
// be called when the lock for the corresponding SecretID is held.
func (b *backend) createAccessor(s logical.Storage, entry *secretIDStorageEntry, hashedSecretID string) error {
	// Create a random accessor
	accessorUUID, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}
	entry.SecretIDAccessor = accessorUUID

	// Create index entry, mapping the accessor to the token ID
	entryIndex := "accessor/" + b.salt.SaltID(entry.SecretIDAccessor)
	if entry, err := logical.StorageEntryJSON(entryIndex, &secretIDAccessorStorageEntry{
		HashedSecretID: hashedSecretID,
	}); err != nil {
		return err
	} else if err = s.Put(entry); err != nil {
		return fmt.Errorf("failed to persist accessor index entry: %s", err)
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

// flushSelectorSecrets deletes all the SecretIDs that belong to the given
// SelectorID.
func (b *backend) flushSelectorSecrets(s logical.Storage, selectorID string) error {
	// Acquire the custom lock to perform listing of SecretIDs
	lock := b.secretIDLock("")
	lock.Lock()
	defer lock.Unlock()
	hashedSecretIDs, err := s.List(fmt.Sprintf("secret_id/%s/", b.salt.SaltID(selectorID)))
	if err != nil {
		return err
	}
	for _, hashedSecretID := range hashedSecretIDs {
		// Acquire the lock belonging to the SecretID
		lock = b.secretIDLock(hashedSecretID)
		lock.Lock()
		entryIndex := fmt.Sprintf("secret_id/%s/%s", b.salt.SaltID(selectorID), hashedSecretID)
		if err := s.Delete(entryIndex); err != nil {
			lock.Unlock()
			return fmt.Errorf("error deleting SecretID %s from storage: %s", hashedSecretID, err)
		}
		lock.Unlock()
	}
	return nil
}
