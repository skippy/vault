package appgroup

import (
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func failOnError(t *testing.T, resp *logical.Response, err error) {
	if resp != nil && resp.IsError() {
		t.Fatalf("error returned in response: %s", resp.Data["error"])
	}
	if err != nil {
		t.Fatal(err)
	}
}

func createBackendWithStorage(t *testing.T) (*backend, *logical.InmemStorage) {
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b, err := createBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatalf("failed to create backend")
	}
	_, err = b.Backend.Setup(config)
	if err != nil {
		t.Fatal(err)
	}
	return b, storage
}

func createBackend(conf *logical.BackendConfig) (*backend, error) {
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
		// UserIDs.
		userIDLocksMap: map[string]*sync.RWMutex{},
	}

	for i := int64(0); i < 256; i++ {
		b.userIDLocksMap[fmt.Sprintf("%2x",
			strconv.FormatInt(i, 16))] = &sync.RWMutex{}
	}
	b.userIDLocksMap["custom"] = &sync.RWMutex{}

	// Attach the paths and secrets that are to be handled by the backend
	b.Backend = &framework.Backend{
		// Register a periodic function that deletes the expired UserID entries
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
				pathTidyUserID(b),
			},
		),
	}
	return b, nil
}
