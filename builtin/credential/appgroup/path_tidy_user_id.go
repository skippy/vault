package appgroup

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathTidySecretID(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tidy/secret-id$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathTidySecretIDUpdate,
		},

		HelpSynopsis:    pathTidySecretIDSyn,
		HelpDescription: pathTidySecretIDDesc,
	}
}

// tidySecretID is used to delete entries in the whitelist that are expired.
func (b *backend) tidySecretID(s logical.Storage) error {
	grabbed := atomic.CompareAndSwapUint32(&b.tidySecretIDCASGuard, 0, 1)
	if grabbed {
		defer atomic.StoreUint32(&b.tidySecretIDCASGuard, 0)
	} else {
		return fmt.Errorf("secret ID tidy operation already running")
	}

	saltedSelectors, err := s.List("secret_id/")
	if err != nil {
		return err
	}

	var result error
	for _, saltedSelector := range saltedSelectors {
		hashedSecrets, err := s.List(fmt.Sprintf("secret_id/%s", saltedSelector))
		if err != nil {
			return err
		}
		for _, hashedSecret := range hashedSecrets {
			entryIndex := fmt.Sprintf("secret_id/%s%s", saltedSelector, hashedSecret)
			secretIDEntry, err := s.Get(entryIndex)
			if err != nil {
				return fmt.Errorf("error fetching secret ID %s: %s", hashedSecret, err)
			}

			if secretIDEntry == nil {
				result = multierror.Append(result, errwrap.Wrapf("[ERR] {{err}}", fmt.Errorf("entry for secret ID %s is nil", hashedSecret)))
				continue
			}

			if secretIDEntry.Value == nil || len(secretIDEntry.Value) == 0 {
				return fmt.Errorf("found entry for secret ID %s but actual secret ID is empty", hashedSecret)
			}

			var result secretIDStorageEntry
			if err := secretIDEntry.DecodeJSON(&result); err != nil {
				return err
			}

			// Unset ExpirationTime indicates non-expiring SecretIDs
			if !result.ExpirationTime.IsZero() && time.Now().UTC().After(result.ExpirationTime) {
				if err := s.Delete(entryIndex); err != nil {
					return fmt.Errorf("error deleting secret ID %s from storage: %s", hashedSecret, err)
				}
			}
		}
	}
	return result
}

// pathTidySecretIDUpdate is used to delete the expired SecretID entries
func (b *backend) pathTidySecretIDUpdate(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, b.tidySecretID(req.Storage)
}

const pathTidySecretIDSyn = "Trigger the clean-up of expired SecretID entries."
const pathTidySecretIDDesc = `SecretIDs will have expiratin time attached to them. The periodic function
of the backend will look for expired entries and delete them. This happens once in a minute. Invoking
this endpoint will trigger the clean-up action, without waiting for the backend's periodic function.`
