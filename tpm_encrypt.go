package tpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMRSAPrivateKey represents an RSA private key stored in the TPM
type TPMRSAPrivateKey struct {
	transport transport.TPM
	handle    tpm2.TPMHandle
	password  string
	hash      crypto.Hash
	publicKey *rsa.PublicKey
}

// Public returns the public key corresponding to the private key, or nil when
// it cannot be read from the TPM. The crypto.Decrypter interface leaves no room
// to report the error, so callers that need one should use loadPublicKey.
func (k *TPMRSAPrivateKey) Public() crypto.PublicKey {
	if k.publicKey == nil {
		// Returning k.publicKey here would hand back a non-nil crypto.PublicKey
		// holding a nil *rsa.PublicKey, which passes a type assertion and
		// panics at the first use.
		if err := k.loadPublicKey(); err != nil {
			return nil
		}
	}
	return k.publicKey
}

// loadPublicKey reads the public key from the TPM
func (k *TPMRSAPrivateKey) loadPublicKey() error {
	readPubCmd := tpm2.ReadPublic{
		ObjectHandle: k.handle,
	}

	readPubRsp, err := readPubCmd.Execute(k.transport)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}

	pubContents, err := readPubRsp.OutPublic.Contents()
	if err != nil {
		return fmt.Errorf("reading public key contents: %w", err)
	}

	if pubContents.Type != tpm2.TPMAlgRSA {
		return fmt.Errorf("key is not RSA, it is algorithm 0x%04x", uint16(pubContents.Type))
	}

	rsaDetail, err := pubContents.Parameters.RSADetail()
	if err != nil {
		return fmt.Errorf("reading RSA details: %w", err)
	}

	rsaUnique, err := pubContents.Unique.RSA()
	if err != nil {
		return fmt.Errorf("reading RSA unique: %w", err)
	}

	k.publicKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(rsaUnique.Buffer),
		E: int(rsaDetail.Exponent),
	}
	if k.publicKey.E == 0 {
		k.publicKey.E = 65537 // Default RSA exponent
	}

	return nil
}

// Decrypt decrypts ciphertext using the TPM-stored private key
func (k *TPMRSAPrivateKey) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	// Determine the scheme and hash algorithm
	var scheme tpm2.TPMTRSADecrypt

	if oaepOpts, ok := opts.(*rsa.OAEPOptions); ok {
		scheme = tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: getTPMHashAlg(oaepOpts.Hash),
				},
			),
		}
	} else {
		// Default to OAEP with SHA256
		scheme = tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: getTPMHashAlg(k.hash),
				},
			),
		}
	}

	// Get the name of the key for authorization
	readPubCmd := tpm2.ReadPublic{
		ObjectHandle: k.handle,
	}
	readPubRsp, err := readPubCmd.Execute(k.transport)
	if err != nil {
		return nil, fmt.Errorf("reading public key for name: %w", err)
	}

	// Perform TPM decryption
	decryptCmd := tpm2.RSADecrypt{
		KeyHandle: tpm2.AuthHandle{
			Handle: k.handle,
			Name:   readPubRsp.Name,
			Auth:   tpm2.PasswordAuth([]byte(k.password)),
		},
		CipherText: tpm2.TPM2BPublicKeyRSA{
			Buffer: ciphertext,
		},
		InScheme: scheme,
		Label:    tpm2.TPM2BData{},
	}

	decryptRsp, err := decryptCmd.Execute(k.transport)
	if err != nil {
		return nil, fmt.Errorf("TPM decryption failed: %w", err)
	}

	return decryptRsp.Message.Buffer, nil
}

// DecryptBlob decrypts a blob using a key stored in the TPM
func DecryptBlob(blob []byte, opts ...TPMOption) ([]byte, error) {
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

	// Create TPM-based private key
	privateKey := &TPMRSAPrivateKey{
		transport: tpm,
		handle:    tpm2.TPMHandle(o.index),
		password:  o.password,
		hash:      o.hash,
	}

	// Use the standard crypto.Decrypter interface
	return privateKey.Decrypt(rand.Reader, blob, &rsa.OAEPOptions{Hash: o.hash})
}

// EncryptBlob encrypts data using a key stored in the TPM.
// It generates or reuses an RSA key in the TPM and encrypts the blob using OAEP padding.
func EncryptBlob(blob []byte, opts ...TPMOption) ([]byte, error) {
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

	// Create TPM-based private key
	privateKey := &TPMRSAPrivateKey{
		transport: tpm,
		handle:    tpm2.TPMHandle(o.index),
		password:  o.password,
		hash:      o.hash,
	}

	// Check if the key already exists by trying to read its public portion
	readPubCmd := tpm2.ReadPublic{
		ObjectHandle: privateKey.handle,
	}

	_, err = readPubCmd.Execute(tpm)
	if err != nil {
		// Key doesn't exist, create it
		_, err = createRSAKey(tpm, o)
		if err != nil {
			return []byte{}, err
		}
	}

	// The handle can already hold a key that is not ours and not RSA, in which
	// case the probe above succeeded and nothing was created. Read the public
	// area here rather than through Public(), which has no way to report that.
	if err := privateKey.loadPublicKey(); err != nil {
		return []byte{}, fmt.Errorf("reading the public key at handle 0x%08x: %w", uint32(o.index), err)
	}

	return encryptWithPublicKey(blob, privateKey.publicKey, o.hash)
}

// createRSAKey creates a new RSA primary key and makes it persistent
func createRSAKey(tpm transport.TPM, o *TPMOptions) (*rsa.PublicKey, error) {
	// Create RSA primary key template
	template := tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgRSA,
		NameAlg:          getTPMHashAlg(o.hash),
		ObjectAttributes: o.keyAttr,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgNull,
				},
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	// Create primary key
	createCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte(o.password)),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(o.password),
				},
			},
		},
		InPublic: tpm2.New2B(template),
	}

	createRsp, err := createCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("creating primary key: %w", err)
	}

	// Make the key persistent
	evictCmd := tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: createRsp.ObjectHandle,
			Name:   createRsp.Name,
		},
		PersistentHandle: tpm2.TPMHandle(o.index),
	}

	_, err = evictCmd.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("making key persistent: %w", err)
	}

	// Extract public key
	pubContents, err := createRsp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("reading public key contents: %w", err)
	}

	rsaDetail, err := pubContents.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("reading RSA details: %w", err)
	}

	rsaUnique, err := pubContents.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("reading RSA unique: %w", err)
	}

	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(rsaUnique.Buffer),
		E: int(rsaDetail.Exponent),
	}
	if pub.E == 0 {
		pub.E = 65537 // Default RSA exponent
	}

	return pub, nil
}

// getTPMHashAlg converts crypto.Hash to TPMAlgID
func getTPMHashAlg(h crypto.Hash) tpm2.TPMAlgID {
	switch h {
	case crypto.SHA1:
		return tpm2.TPMAlgSHA1
	case crypto.SHA256:
		return tpm2.TPMAlgSHA256
	case crypto.SHA384:
		return tpm2.TPMAlgSHA384
	case crypto.SHA512:
		return tpm2.TPMAlgSHA512
	default:
		return tpm2.TPMAlgSHA256 // Default to SHA256
	}
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
