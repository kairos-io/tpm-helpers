package tpm

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

// StoreBlob stores binary data in the TPM's Non-Volatile (NV) storage.
// Used for local passphrase storage in offline encryption mode.
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

	// Create the TPMS_NV_PUBLIC structure
	nvPublic := tpm2.TPMSNVPublic{
		NVIndex:    tpm2.TPMHandle(o.index),
		NameAlg:    tpm2.TPMAlgSHA256,
		Attributes: o.nvAttr,
		DataSize:   uint16(len(blob)), // Use actual blob size
	}

	// Define the NV space
	defineCmd := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte(o.password),
		},
		PublicInfo: tpm2.New2B(nvPublic),
	}

	// Define the NV space. If it already exists, continue with writing.
	_, err = defineCmd.Execute(tpm)
	if err != nil {
		// Check if this is a "space already defined" error
		if !isNVSpaceAlreadyDefined(err) {
			return fmt.Errorf("defining NV space: %w", err)
		}
		// NV space already exists, continue with writing
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

	// Read the public info to get the data size
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

// UndefineBlob removes an NV index from the TPM's Non-Volatile storage.
func UndefineBlob(opts ...TPMOption) error {
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

	// Undefine the NV space
	undefineCmd := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte(o.password)),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(o.index),
			Name:   tpm2.TPM2BName{}, // Will be computed if needed
		},
	}

	_, err = undefineCmd.Execute(tpm)
	if err != nil {
		return fmt.Errorf("undefining NV space: %w", err)
	}

	return nil
}

// isNVSpaceAlreadyDefined checks if the error indicates that the NV space is already defined.
func isNVSpaceAlreadyDefined(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's the specific TPM error code
	var tpmErr tpm2.TPMRC
	if errors.As(err, &tpmErr) {
		return tpmErr == tpm2.TPMRCNVDefined
	}

	// Fallback to string matching for other error formats
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "nv_defined") ||
		strings.Contains(errStr, "already defined") ||
		strings.Contains(errStr, "index already")
}
