//go:build !windows

package backend

import (
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// OpenTransport opens a TPM transport for the given device path.
// When path is empty, it tries /dev/tpmrm0 then /dev/tpm0.
func OpenTransport(path string) (transport.TPMCloser, error) {
	if path == "" {
		tpm, err := linuxtpm.Open("/dev/tpmrm0")
		if err != nil {
			if os.IsNotExist(err) {
				return linuxtpm.Open("/dev/tpm0")
			}
			return nil, err
		}
		return tpm, nil
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if fi.Mode()&os.ModeSocket != 0 {
		return linuxudstpm.Open(path)
	}

	return linuxtpm.Open(path)
}
