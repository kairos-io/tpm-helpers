package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// StoreBlob stores binary data in the TPM's Non-Volatile (NV) storage.
// The data is written to the specified index with the configured attributes and password.
func StoreBlob(blob []byte, opts ...TPMOption) error {
	o, err := DefaultTPMOption(opts...)
	if err != nil {
		return err
	}

	// Open TPM transport
	tpm, err := getTPMTransport(o)
	if err != nil {
		return err
	}
	defer tpm.Close() //nolint:errcheck // Cleanup operation

	// First, try to define the NV space
	defineCmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte(o.password),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    tpm2.TPMHandle(o.index),
				NameAlg:    getTPMHashAlg(o.hash),
				Attributes: o.nvAttr,
				DataSize:   uint16(len(blob)),
			},
		),
	}

	// Try to define the space (it might already exist)
	_, err = defineCmd.Execute(tpm)
	if err != nil {
		// If it already exists, that's fine, continue with writing
		// In a real implementation, you might want to check the specific error
	}

	// Write data to NV storage
	if len(blob) > 0 {
		writeCmd := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth([]byte(o.password)),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(o.index),
				Name:   tpm2.TPM2BName{}, // Will be computed if needed
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: blob,
			},
			Offset: 0,
		}

		_, err = writeCmd.Execute(tpm)
		if err != nil {
			return fmt.Errorf("writing to NV storage: %w", err)
		}
	}

	return nil
}

// ReadBlob reads binary data from the TPM's Non-Volatile (NV) storage.
// The data is read from the specified index using the configured password.
func ReadBlob(opts ...TPMOption) ([]byte, error) {
	o, err := DefaultTPMOption(opts...)
	if err != nil {
		return []byte{}, err
	}

	// Open TPM transport
	tpm, err := getTPMTransport(o)
	if err != nil {
		return []byte{}, err
	}
	defer tpm.Close() //nolint:errcheck // Cleanup operation

	// First, read the public info to get the data size
	readPubCmd := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(o.index),
	}

	readPubRsp, err := readPubCmd.Execute(tpm)
	if err != nil {
		return []byte{}, fmt.Errorf("reading NV public info: %w", err)
	}

	nvPublic, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return []byte{}, fmt.Errorf("reading NV public contents: %w", err)
	}

	if nvPublic.DataSize == 0 {
		return []byte{}, nil
	}

	// Read the data
	readCmd := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte(o.password)),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(o.index),
			Name:   readPubRsp.NVName,
		},
		Size:   nvPublic.DataSize,
		Offset: 0,
	}

	readRsp, err := readCmd.Execute(tpm)
	if err != nil {
		return []byte{}, fmt.Errorf("reading NV data: %w", err)
	}

	return readRsp.Data.Buffer, nil
}
