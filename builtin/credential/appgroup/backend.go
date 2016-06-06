package appgroup

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type backend struct {
	*framework.Backend
	salt *salt.Salt

	// Guard to clean-up the expired SecretID entries
	tidySecretIDCASGuard uint32

	// Lock to make changes to registered Apps
	appLock *sync.RWMutex

	// Lock to make changes to registered Groups
	groupLock *sync.RWMutex

	// Lock to make changes to "supergroup" mode storage entries
	superGroupLock *sync.RWMutex

	// Map of locks to make changes to the SecretIDs generated
	selectorIDLocksMap map[string]*sync.RWMutex

	// Map of locks to make changes to the SecretIDs generated
	secretIDLocksMap map[string]*sync.RWMutex
}

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	return b.Setup(conf)
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	// Initialize the salt
	salt, err := salt.NewSalt(conf.StorageView, &salt.Config{
		HashFunc: salt.SHA256Hash,
	})
	if err != nil {
		return nil, err
	}

	// Create a backend object
	b := &backend{
		// Set the salt object for the backend
		salt: salt,

		// Create the lock for making changes to the Apps registered with the backend
		appLock: &sync.RWMutex{},

		// Create the lock for making changes to the Groups registered with the backend
		groupLock: &sync.RWMutex{},

		// Create the lock for making changes to the storage entries of "supergroup" mode
		superGroupLock: &sync.RWMutex{},

		// Create the map of locks to modify the generated SelectorIDs.
		selectorIDLocksMap: map[string]*sync.RWMutex{},

		// Create the map of locks to modify the generated SecretIDs.
		secretIDLocksMap: map[string]*sync.RWMutex{},
	}

	for i := int64(0); i < 256; i++ {
		b.selectorIDLocksMap[fmt.Sprintf("%2x", strconv.FormatInt(i, 16))] = &sync.RWMutex{}
		b.secretIDLocksMap[fmt.Sprintf("%2x", strconv.FormatInt(i, 16))] = &sync.RWMutex{}
	}
	b.secretIDLocksMap["custom"] = &sync.RWMutex{}

	// Ideally, "custom" entry is not required for selectorIDLocksMap since
	// selectorID is always generated internally and is a UUID. But having
	// one is safe. The getter method for lock will never be nil if it can
	// always fallback on the "custom" lock.
	b.selectorIDLocksMap["custom"] = &sync.RWMutex{}

	// Attach the paths and secrets that are to be handled by the backend
	b.Backend = &framework.Backend{
		// Register a periodic function that deletes the expired SecretID entries
		PeriodicFunc: b.periodicFunc,
		Help:         backendHelp,
		AuthRenew:    b.pathLoginRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: framework.PathAppend(
			appPaths(b),
			groupPaths(b),
			superGroupPaths(b),
			[]*framework.Path{
				pathLogin(b),
				pathTidySecretID(b),
			},
		),
	}
	return b, nil
}

// periodicFunc of the backend will be invoked once a minute by the RollbackManager.
// AppGroup backend utilizes this function to delete expired SecretID entries.
// This could mean that the SecretID may live in the backend upto 1min after its
// expiration. The deletion of SecretIDs are not security sensitive and it is okay
// to delay the removal of SecretIDs by a minute.
func (b *backend) periodicFunc(req *logical.Request) error {
	// Initiate clean-up of expired SecretID entries
	b.tidySecretID(req.Storage)
	return nil
}

const backendHelp = `Any registered App(s) or Group(s) of Apps can authenticate themselves
with Vault using SecretIDs that are specifically generated to serve that
purpose. The SecretIDs have nice properties like usage-limit and expiration,
that can address numerous use-cases. An App can represent a service, or
a machine or anything that can be IDed. Since an App can be a machine in
itself, the AppGroup backend is a potential successor for the App-ID backend.`
