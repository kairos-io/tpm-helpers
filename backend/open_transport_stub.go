//go:build !linux

package backend

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

// OpenTransport is only supported on Linux.
func OpenTransport(string) (transport.TPMCloser, error) {
	return nil, errors.New("tpm-helpers TPM transport is only supported on Linux")
}
