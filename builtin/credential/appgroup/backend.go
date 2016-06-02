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

	// Map of locks to make changes to the SecretIDs created.
	// The lock in the map will be keyed off of SecretID itself.
	// Each SecretID will have a separate lock which is used to
	// update the information related to it, 'num_uses' for example.
	// The lock will be deleted when the SecretID is delted.
	secretIDLocksMap map[string]*sync.RWMutex
}

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	return b.Setup(conf)
}

func Backend(conf *logical.BackendConfig) (*framework.Backend, error) {
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

		// Create the map of locks to hold locks that are used to modify the created
		// SecretIDs.
		secretIDLocksMap: map[string]*sync.RWMutex{},
	}

	for i := int64(0); i < 256; i++ {
		b.secretIDLocksMap[fmt.Sprintf("%2x",
			strconv.FormatInt(i, 16))] = &sync.RWMutex{}
	}
	b.secretIDLocksMap["custom"] = &sync.RWMutex{}

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
	return b.Backend, nil
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
