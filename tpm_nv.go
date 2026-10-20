package tpm

import (
	"errors"
	"fmt"
	"math"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
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

	// An NV index's size is a uint16, so a larger blob would be stored under a
	// truncated size and read back short.
	if len(blob) > math.MaxUint16 {
		return fmt.Errorf("blob of %d bytes does not fit an NV index, the maximum is %d", len(blob), math.MaxUint16)
	}

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

	// Define the NV space. An index keeps the size it was defined with, and the
	// TPM ignores the size carried by a define that hits an index which already
	// exists. Writing a shorter blob into a larger index leaves the tail of the
	// previous blob in place, and ReadBlob returns the whole index, so the
	// caller gets its new blob spliced onto the old one and no error. A store is
	// a full overwrite, so replace an index whose size does not match.
	if _, err = defineCmd.Execute(tpm); err != nil {
		if !isNVSpaceAlreadyDefined(err) {
			return fmt.Errorf("defining NV space: %w", err)
		}
		if err := resizeNVSpace(tpm, o, nvPublic.DataSize, defineCmd); err != nil {
			return err
		}
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

	return undefineNVSpace(tpm, o, tpm2.TPM2BName{})
}

// undefineNVSpace removes an NV index over an already open transport. The name
// is only needed when the index is addressed by name; the zero value lets the
// TPM compute it.
func undefineNVSpace(t transport.TPM, o *TPMOptions, name tpm2.TPM2BName) error {
	undefineCmd := tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte(o.password)),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(o.index),
			Name:   name,
		},
	}

	if _, err := undefineCmd.Execute(t); err != nil {
		return fmt.Errorf("undefining NV space: %w", err)
	}

	return nil
}

// resizeNVSpace replaces an already defined NV index with one of the size the
// caller asked for, and does nothing when the sizes already match. An index is
// therefore only destroyed when the blob being stored could not have replaced
// its contents in full anyway.
func resizeNVSpace(t transport.TPM, o *TPMOptions, want uint16, defineCmd tpm2.NVDefineSpace) error {
	readPubCmd := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(o.index),
	}

	readPubRsp, err := readPubCmd.Execute(t)
	if err != nil {
		return fmt.Errorf("reading NV public info of the existing index: %w", err)
	}

	nvPublic, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return fmt.Errorf("reading NV public contents of the existing index: %w", err)
	}

	if nvPublic.DataSize == want {
		return nil
	}

	if err := undefineNVSpace(t, o, readPubRsp.NVName); err != nil {
		return fmt.Errorf("replacing the NV index defined for %d bytes: %w", nvPublic.DataSize, err)
	}

	if _, err := defineCmd.Execute(t); err != nil {
		return fmt.Errorf("redefining NV space for %d bytes: %w", want, err)
	}

	return nil
}

// isNVSpaceAlreadyDefined checks if the error indicates that the NV space is already defined.
func isNVSpaceAlreadyDefined(err error) bool {
	return err != nil && errors.Is(err, tpm2.TPMRCNVDefined)
}
