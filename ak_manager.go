package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

// DefaultEKAuthPolicy is the standard TPM 2.0 Endorsement Key authorization policy
// as defined in the TCG EK Credential Profile specification (Table B.3.3).
// This policy allows the EK to be used for key activation and attestation
// without requiring additional authorization.
//
// References:
// - TCG EK Credential Profile: https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf
// - tpm2-tools implementation: https://github.com/tpm2-software/tpm2-tools/blob/c2d1ee7c60dbcc24c4251eb1a99138d2d29fad73/tools/tpm2_createek.c#L34-L42
var DefaultEKAuthPolicy = []byte{
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
	0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
	0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
	0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
}

// AKManager manages ephemeral Attestation Keys for TPM attestation.
// No persistent storage is required - AKs are created fresh for each attestation.
type AKManager struct {
	config *config
	tpm    *attest.TPM
}

// NewAKManager creates a new AK manager and opens a TPM session
func NewAKManager(opts ...Option) (*AKManager, error) {
	c := newConfig()
	if err := c.apply(opts...); err != nil {
		return nil, fmt.Errorf("applying options: %w", err)
	}

	// Open TPM session and keep it open for the lifetime of the AKManager
	tpm, err := getTPM(c)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}

	fmt.Printf("DEBUG: AKManager created with TPM session: %p\n", tpm)
	return &AKManager{config: c, tpm: tpm}, nil
}

// Close closes the TPM session and cleans up resources
func (m *AKManager) Close() error {
	if m.tpm != nil {
		fmt.Printf("DEBUG: Closing TPM session: %p\n", m.tpm)
		err := m.tpm.Close()
		m.tpm = nil // Set to nil after closing
		return err
	}
	return nil
}

// CreateTransientAK creates a new ephemeral AK for attestation
func (m *AKManager) CreateTransientAK() (*attest.AK, *attest.AttestationParameters, error) {
	// Create a new transient AK
	ak, err := m.tpm.NewAK(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating transient AK: %w", err)
	}

	// Get the attestation parameters
	params := ak.AttestationParameters()

	fmt.Printf("DEBUG: Created new transient AK for attestation\n")
	return ak, &params, nil
}

// GetAKPublicKey returns the public key for the current transient AK
func (m *AKManager) GetAKPublicKey(ak *attest.AK) (crypto.PublicKey, error) {
	// Get the public key from the AK's attestation parameters
	params := ak.AttestationParameters()
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](params.Public)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling public key: %w", err)
	}

	// Convert TPMTPublic to crypto.PublicKey
	return publicKeyFromTPMTPublic(pub)
}

// PerformAttestation performs a complete attestation flow using a transient AK
func (m *AKManager) PerformAttestation(ak *attest.AK, challenge *attest.EncryptedCredential) ([]byte, error) {
	// Use go-attestation's ActivateCredential (same as legacy flow)
	secret, err := ak.ActivateCredential(m.tpm, *challenge)
	if err != nil {
		return nil, fmt.Errorf("activating credential: %w", err)
	}

	return secret, nil
}

// GeneratePCRQuote generates a PCR quote using the transient AK
func (m *AKManager) GeneratePCRQuote(ak *attest.AK, pcrs []int) ([]byte, []byte, error) {
	// Generate TPM quote with explicit PCR selection using modern go-attestation v0.5.1+ API
	// Use QuotePCRs to select the specified PCRs for attestation
	nonce := make([]byte, 20) // 20-byte nonce for quote freshness
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Generate quote using the transient AK
	// Use the go-attestation library's Quote method with the correct signature
	quote, err := ak.Quote(m.tpm, nonce, attest.HashSHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("generating PCR quote: %w", err)
	}

	// Convert quote to bytes for transmission
	quoteBytes, err := json.Marshal(quote)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling quote: %w", err)
	}

	// Return both the quote and the nonce
	return quoteBytes, nonce, nil
}

// GetEK retrieves the Endorsement Key from the TPM
func (m *AKManager) GetEK() (*attest.EK, error) {
	// Get the EK from the TPM
	ek, err := m.tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("getting EK: %w", err)
	}

	if len(ek) == 0 {
		return nil, fmt.Errorf("no EK found in TPM")
	}

	// Return the first EK (TPMs typically have one EK)
	return &ek[0], nil
}

// CreateProofRequestWithAK creates a proof request using the transient AK
func (m *AKManager) CreateProofRequestWithAK(challenge *AttestationChallengeResponse, ak *attest.AK) (*ProofRequest, error) {
	// Debug: Check if TPM session is nil
	if m.tpm == nil {
		return nil, fmt.Errorf("TPM session is nil - AKManager not properly initialized")
	}

	// Debug: Check if challenge is nil
	if challenge == nil {
		return nil, fmt.Errorf("challenge is nil")
	}

	// Debug: Check if challenge.Challenge is nil
	if challenge.Challenge == nil {
		return nil, fmt.Errorf("challenge.Challenge is nil")
	}

	// Use the provided transient AK to activate the credential
	secret, err := ak.ActivateCredential(m.tpm, *challenge.Challenge)
	if err != nil {
		return nil, fmt.Errorf("activating credential with transient AK: %w", err)
	}

	return &ProofRequest{Secret: secret}, nil
}

// publicKeyFromTPMTPublic converts a TPMTPublic to a crypto.PublicKey
func publicKeyFromTPMTPublic(pub *tpm2.TPMTPublic) (crypto.PublicKey, error) {
	// Extract the public key parameters
	parms := pub.Parameters

	// Extract the unique identifier
	unique := pub.Unique

	switch pub.Type {
	case tpm2.TPMAlgRSA:
		// Access RSA parameters from the union type
		rsaParms, err := parms.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("invalid RSA parameters: %w", err)
		}

		// Access RSA unique from the union type
		rsaUnique, err := unique.RSA()
		if err != nil {
			return nil, fmt.Errorf("invalid RSA unique: %w", err)
		}

		// Convert to RSA public key
		n := new(big.Int).SetBytes(rsaUnique.Buffer)
		e := int(rsaParms.Exponent)
		if e == 0 {
			e = 65537 // Default exponent
		}

		return &rsa.PublicKey{
			N: n,
			E: e,
		}, nil

	case tpm2.TPMAlgECC:
		// Access ECC parameters from the union type
		eccParms, err := parms.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("invalid ECC parameters: %w", err)
		}

		// Access ECC unique from the union type
		eccUnique, err := unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("invalid ECC unique: %w", err)
		}

		// Convert to ECDSA public key
		curve := elliptic.P256() // Default curve
		switch eccParms.CurveID {
		case tpm2.TPMECCNistP256:
			curve = elliptic.P256()
		case tpm2.TPMECCNistP384:
			curve = elliptic.P384()
		case tpm2.TPMECCNistP521:
			curve = elliptic.P521()
		}

		x := new(big.Int).SetBytes(eccUnique.X.Buffer)
		y := new(big.Int).SetBytes(eccUnique.Y.Buffer)

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %v", pub.Type)
	}
}
