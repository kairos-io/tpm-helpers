package tpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/folbricht/tpmk"
	"github.com/pkg/errors"
)

// DecryptBlob decrypts a blob using a key stored in the TPM
func DecryptBlob(blob []byte, opts ...TPMOption) ([]byte, error) {
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

	private, err := tpmk.NewRSAPrivateKey(dev, o.index, o.password)
	if err != nil {
		return []byte{}, fmt.Errorf("loading private key: '%w'", err)
	}
	return private.Decrypt(rand.Reader, blob, &rsa.OAEPOptions{Hash: o.hash})
}

// EncryptBlob encrypts data using a key stored in the TPM.
// It generates or reuses an RSA key in the TPM and encrypts the blob using OAEP padding.
func EncryptBlob(blob []byte, opts ...TPMOption) ([]byte, error) {
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

	// Get a list of keys
	keys, err := tpmk.KeyList(dev)
	if err != nil {
		return []byte{}, errors.Wrap(err, "reading key list")
	}

	exists := false
	// Print the key handles in hex notation
	for _, hh := range keys {
		if o.index == hh {
			exists = true
		}
	}

	var pub crypto.PublicKey
	if !exists {
		// Generate the key if doesn't exist
		pub, err = tpmk.GenRSAPrimaryKey(dev, o.index, "", o.password, o.keyAttr)
		if err != nil {
			return []byte{}, err
		}
	} else {
		// Re-Use the private key in the TPM
		private, err := tpmk.NewRSAPrivateKey(dev, o.index, o.password)
		if err != nil {
			return []byte{}, err
		}
		pub = private.Public()
	}

	p, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keypair returned by TPM is malformed: pubkey is not an RSA public key")
	}

	return encryptWithPublicKey(blob, p, o.hash)
}

// encryptWithPublicKey encrypts data with public key
func encryptWithPublicKey(msg []byte, pub *rsa.PublicKey, c crypto.Hash) ([]byte, error) {
	var h hash.Hash

	switch c {
	case crypto.SHA256:
		h = sha256.New()
	default:
		return []byte{}, fmt.Errorf("unsupported encryption type")
	}

	return rsa.EncryptOAEP(h, rand.Reader, pub, msg, nil)
}
