package tpm

import (
	"github.com/folbricht/tpmk"
)

// StoreBlob stores binary data in the TPM's Non-Volatile (NV) storage.
// The data is written to the specified index with the configured attributes and password.
func StoreBlob(blob []byte, opts ...TPMOption) error {
	o, err := DefaultTPMOption(opts...)
	if err != nil {
		return err
	}

	// Open device or simulator
	dev, err := getTPMDevice(o)
	if err != nil {
		return err
	}
	if !o.emulated {
		defer dev.Close() //nolint:errcheck // Cleanup operation //nolint:errcheck // Cleanup operation
	}

	// Write to the index
	return tpmk.NVWrite(dev, o.index, blob, o.password, o.nvAttr)
}

// ReadBlob reads binary data from the TPM's Non-Volatile (NV) storage.
// The data is read from the specified index using the configured password.
func ReadBlob(opts ...TPMOption) ([]byte, error) {
	o, err := DefaultTPMOption(opts...)
	if err != nil {
		return []byte{}, err
	}

	// Open device or simulator
	dev, err := getTPMDevice(o)
	if err != nil {
		return []byte{}, err
	}
	if !o.emulated {
		defer dev.Close() //nolint:errcheck // Cleanup operation //nolint:errcheck // Cleanup operation
	}

	// Read the data
	return tpmk.NVRead(dev, o.index, o.password)
}
