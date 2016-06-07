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

	// The salt value to be used by the information to be accessed only
	// by this backend.
	salt *salt.Salt

	// Guard to clean-up the expired SecretID entries
	tidySecretIDCASGuard uint32

	// Lock to make changes to registered Apps. This is a low-traffic
	// operation. So, using a single lock would suffice.
	appLock *sync.RWMutex

	// Lock to make changes to registered Groups. This is a low-traffic
	// operation. So, using a single lock would suffice.
	groupLock *sync.RWMutex

	// Lock to make changes to storage entries belonging to "supergroup"
	superGroupLock *sync.RWMutex

	// Map of locks to make changes to the storage entries of SelectorIDs
	// generated. This will be initiated to a predefined number of locks
	// when the backend is created, and will be indexed based on the salted
	// selector IDs.
	selectorIDLocksMap map[string]*sync.RWMutex

	// Map of locks to make changes to the storage entries of SecretIDs
	// generated. This will be initiated to a predefined number of locks
	// when the backend is created, and will be indexed based on the hashed
	// secret IDs.
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

	// Create a predefined number (256) of locks. This will avoid a superfluous number
	// of locks directly proportional to the number of selectorID/secretIDs. These locks
	// can be accessed by indexing based on the first 2 characters of the selectorID or
	// the secretID respectively. Since these are randomly generated, uniformity of access
	// is guaranteed.
	for i := int64(0); i < 256; i++ {
		b.selectorIDLocksMap[fmt.Sprintf("%2x", strconv.FormatInt(i, 16))] = &sync.RWMutex{}
		b.secretIDLocksMap[fmt.Sprintf("%2x", strconv.FormatInt(i, 16))] = &sync.RWMutex{}
	}

	// Have an extra lock, in case the indexing does not result in a lock, this can be used.
	// These locks can be used for listing purposes as well.
	b.secretIDLocksMap["custom"] = &sync.RWMutex{}
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
// This could mean that the SecretID may live in the backend upto 1 min after its
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
