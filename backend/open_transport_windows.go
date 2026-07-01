//go:build windows

package backend

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// OpenTransport opens a TPM transport on Windows via TBS.
func OpenTransport(string) (transport.TPMCloser, error) {
	return windowstpm.Open()
}
