package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

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

// akBlob represents the AK data stored on disk and provides controlled access to AK information.
// The struct itself is unexported to prevent external direct access and maintain encapsulation,
// but the fields are exported to enable JSON marshaling/unmarshaling for persistence.
// External access is provided through controlled methods on AKManager.
type akBlob struct {
	AKBytes           []byte `json:"ak_bytes"`           // Marshaled go-attestation AK
	AttestationParams []byte `json:"attestation_params"` // Serialized AttestationParameters from go-attestation
}

// getAttestationParameters deserializes and returns the AttestationParameters
func (b *akBlob) getAttestationParameters() (*attest.AttestationParameters, error) {
	if len(b.AttestationParams) == 0 {
		return nil, fmt.Errorf("AttestationParams field is empty in AK blob")
	}

	var params attest.AttestationParameters
	if err := json.Unmarshal(b.AttestationParams, &params); err != nil {
		return nil, fmt.Errorf("unmarshaling attestation parameters: %w", err)
	}
	return &params, nil
}

// getPublicKeyBytes returns the raw AK public key bytes for transmission
func (b *akBlob) getPublicKeyBytes() ([]byte, error) {
	params, err := b.getAttestationParameters()
	if err != nil {
		return nil, err
	}
	return params.Public, nil
}

// getAKBytes returns the marshaled AK bytes for later loading
func (b *akBlob) getAKBytes() []byte {
	return b.AKBytes
}

// AKManager manages Attestation Key lifecycle using blob storage
type AKManager struct {
	akBlobFile string // File path for storing the TPM-encrypted AK blob
	config     *config
}

// NewAKManager creates a new AK manager instance
// Requires WithAKHandleFile option to specify where to store/load the AK blob
func NewAKManager(opts ...Option) (*AKManager, error) {
	c := newConfig()
	if err := c.apply(opts...); err != nil {
		return nil, fmt.Errorf("applying options: %w", err)
	}

	if c.akHandleFile == "" {
		return nil, fmt.Errorf("AK blob file path is required - use WithAKHandleFile option")
	}

	return &AKManager{
		akBlobFile: c.akHandleFile,
		config:     c,
	}, nil
}

// GetOrCreateAK returns the AK public key bytes, creating the AK if it doesn't exist
func (m *AKManager) GetOrCreateAK() ([]byte, error) {
	// Check if AK blob file already exists
	if m.akExists() {
		// Check file size and basic info
		if stat, err := os.Stat(m.akBlobFile); err == nil {
			// If file is empty, it's likely corrupted - return error for manual intervention
			if stat.Size() == 0 {
				return nil, fmt.Errorf("AK blob file exists but is empty (0 bytes) - this indicates corruption. Please remove the file manually and retry: %s", m.akBlobFile)
			}

			// If file is suspiciously small, it might be corrupted - return error for manual intervention
			if stat.Size() < 50 {
				return nil, fmt.Errorf("AK blob file is suspiciously small (%d bytes) - this may indicate corruption. Please verify the file or remove it manually and retry: %s", stat.Size(), m.akBlobFile)
			}
		}

		// Load existing AK and return public key
		akBlob, err := m.LoadAK()
		if err != nil {
			return nil, fmt.Errorf("failed to load existing AK blob file (this may indicate corruption or version mismatch). Please verify the file or remove it manually and retry. File: %s, Error: %w", m.akBlobFile, err)
		}

		publicKeyBytes, err := akBlob.getPublicKeyBytes()
		if err != nil {
			return nil, fmt.Errorf("getting public key bytes: %w", err)
		}

		return publicKeyBytes, nil
	}

	// Create new AK
	return m.createAndStoreAK()
}

// akExists checks if the AK blob file exists
func (m *AKManager) akExists() bool {
	_, err := os.Stat(m.akBlobFile)
	return err == nil
}

// GetAKPublicKey returns the public key for the current AK
func (m *AKManager) GetAKPublicKey() (crypto.PublicKey, error) {
	// Open TPM using go-attestation
	tpm, err := getTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close() //nolint:errcheck

	// Load AK and get its public key
	akBlob, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}

	ak, err := tpm.LoadAK(akBlob.getAKBytes())
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer ak.Close(tpm) //nolint:errcheck

	// Get the public key from the AK's attestation parameters
	params := ak.AttestationParameters()
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](params.Public)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling public key: %w", err)
	}

	// Convert TPMTPublic to crypto.PublicKey
	return publicKeyFromTPMTPublic(pub)
}

// CleanupAK removes the AK blob file
func (m *AKManager) CleanupAK() error {
	// Remove the AK blob file
	err := os.Remove(m.akBlobFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing AK blob file: %w", err)
	}
	return nil
}

// WithAKHandleFile sets the file path for storing AK handle information
// This is required for all AK operations - callers must specify where to store the handle
func WithAKHandleFile(path string) Option {
	return func(c *config) error {
		c.akHandleFile = path
		return nil
	}
}

// createAndStoreAK creates a new AK using go-attestation and stores it to file
func (m *AKManager) createAndStoreAK() ([]byte, error) {
	// Open TPM using go-attestation (same as legacy flow)
	tpm, err := getTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close() //nolint:errcheck

	// Create AK using go-attestation (same as legacy flow)
	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, fmt.Errorf("creating AK: %w", err)
	}
	defer ak.Close(tpm) //nolint:errcheck

	// Get AttestationParameters
	params := ak.AttestationParameters()

	// Marshal the AK for storage
	akBytes, err := ak.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling AK: %w", err)
	}

	// Serialize the AttestationParameters for storage
	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshaling attestation parameters: %w", err)
	}

	// Create the AK blob structure
	akBlob := akBlob{
		AKBytes:           akBytes,
		AttestationParams: paramsBytes,
	}

	// Store the blob to file
	if err := m.saveAKBlob(&akBlob); err != nil {
		return nil, fmt.Errorf("saving AK blob: %w", err)
	}

	// Return the public key bytes (same format as legacy flow)
	return params.Public, nil
}

// saveAKBlob saves the AK blob to the configured file
func (m *AKManager) saveAKBlob(blob *akBlob) error {
	// Ensure directory exists
	dir := filepath.Dir(m.akBlobFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	// Marshal to JSON
	data, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("marshaling AK blob: %w", err)
	}

	// Write to file
	return os.WriteFile(m.akBlobFile, data, 0600)
}

// LoadAK loads the AK from the blob file
func (m *AKManager) LoadAK() (*akBlob, error) {
	// Load AK blob from file
	blob, err := m.loadAKBlob()
	if err != nil {
		return nil, fmt.Errorf("loading AK blob: %w", err)
	}

	return blob, nil
}

// GetAKPublicKeyBytes returns the raw AK public key bytes (for testing)
func (m *AKManager) GetAKPublicKeyBytes() ([]byte, error) {
	akBlob, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	return akBlob.getPublicKeyBytes()
}

// GetStoredAKBytes returns the marshaled AK bytes (for testing)
func (m *AKManager) GetStoredAKBytes() ([]byte, error) {
	akBlob, err := m.LoadAK()
	if err != nil {
		return nil, err
	}
	return akBlob.getAKBytes(), nil
}

// loadAKBlob loads the AK blob from the configured file
func (m *AKManager) loadAKBlob() (*akBlob, error) {
	data, err := os.ReadFile(m.akBlobFile)
	if err != nil {
		return nil, fmt.Errorf("reading AK blob file: %w", err)
	}

	var blob akBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil, fmt.Errorf("unmarshaling AK blob: %w", err)
	}

	return &blob, nil
}

// GetAttestationData returns the EK and AttestationParameters for challenge generation
// This provides go-attestation native types instead of wrapper structs
func (m *AKManager) GetAttestationData() (*attest.EK, *attest.AttestationParameters, error) {
	// Get EK using existing function
	ek, err := getEK(m.config)
	if err != nil {
		return nil, nil, fmt.Errorf("getting EK: %w", err)
	}

	// Get AK AttestationParameters from our persisted AK
	akBlob, err := m.LoadAK()
	if err != nil {
		return nil, nil, fmt.Errorf("loading AK: %w", err)
	}

	attestationParams, err := akBlob.getAttestationParameters()
	if err != nil {
		return nil, nil, fmt.Errorf("getting attestation parameters: %w", err)
	}

	return ek, attestationParams, nil
}

// CreateProofRequest creates a proof request with the activated credential secret and quote
func (m *AKManager) CreateProofRequest(challengeResp *AttestationChallengeResponse) (*ProofRequest, error) {
	// Activate the credential to get the secret
	challenge := &Challenge{EC: challengeResp.Challenge}
	secret, err := m.ActivateCredential(challenge)
	if err != nil {
		return nil, fmt.Errorf("activating credential: %w", err)
	}

	// Generate a fresh PCR quote for cryptographic proof
	// Use PCRs 0, 7, 11 for boot integrity verification by default
	quote, err := m.generatePCRQuote(0, 7, 11)
	if err != nil {
		return nil, fmt.Errorf("generating quote: %w", err)
	}

	return &ProofRequest{
		Secret:   secret,
		PCRQuote: quote, // Cryptographic proof of TPM state
	}, nil
}

// Challenge represents a simple credential activation challenge
type Challenge struct {
	EC *attest.EncryptedCredential
}

// ActivateCredential decrypts a credential blob using go-attestation
// Takes the challenge received from server and returns the recovered secret
func (m *AKManager) ActivateCredential(challenge *Challenge) ([]byte, error) {
	// Open TPM using go-attestation
	tpm, err := getTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close() //nolint:errcheck

	// Load AK using go-attestation (same as legacy flow)
	akBlob, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK info: %w", err)
	}

	// Load the marshaled AK using go-attestation
	ak, err := tpm.LoadAK(akBlob.getAKBytes())
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer ak.Close(tpm) //nolint:errcheck

	// Use go-attestation's ActivateCredential (same as legacy flow)
	secret, err := ak.ActivateCredential(tpm, *challenge.EC)
	if err != nil {
		return nil, fmt.Errorf("activating credential: %w", err)
	}

	return secret, nil
}

// generatePCRQuote generates a TPM quote (signed attestation) of specified PCR values using the AK
// pcrs: variadic list of PCR indices to include in the quote (e.g., 0, 7, 11)
func (m *AKManager) generatePCRQuote(pcrs ...int) ([]byte, error) {
	// Validate PCR arguments
	if len(pcrs) == 0 {
		return nil, fmt.Errorf("at least one PCR index must be specified")
	}

	for _, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return nil, fmt.Errorf("PCR index %d is out of range (0-23)", pcr)
		}
	}
	// Open TPM using go-attestation
	tpm, err := getTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close() //nolint:errcheck

	// Load AK using go-attestation
	akBlob, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK info: %w", err)
	}

	ak, err := tpm.LoadAK(akBlob.getAKBytes())
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer ak.Close(tpm) //nolint:errcheck

	// Generate TPM quote with explicit PCR selection using modern go-attestation v0.5.1+ API
	// Use QuotePCRs to select the specified PCRs for attestation
	nonce := make([]byte, 20) // 20-byte nonce for quote freshness
	quote, err := ak.QuotePCRs(tpm, nonce, attest.HashSHA256, pcrs)
	if err != nil {
		return nil, fmt.Errorf("generating PCR quote: %w", err)
	}

	// The Quote struct only contains the quote data, but we need PCR values too
	// Read all PCR values from the TPM
	allPCRs, err := tpm.PCRs(attest.HashSHA256)
	if err != nil {
		return nil, fmt.Errorf("reading PCRs: %w", err)
	}

	// Extract only the requested PCR values
	selectedPCRValues := make(map[int][]byte)
	for _, pcrIndex := range pcrs {
		if pcrIndex < len(allPCRs) {
			selectedPCRValues[pcrIndex] = allPCRs[pcrIndex].Digest
		}
	}

	// Create a structure that includes both the quote and PCR values
	// This is flexible for any number of PCRs
	quoteData := struct {
		Quote struct {
			Version   string `json:"version"`
			Quote     []byte `json:"quote"`
			Signature []byte `json:"signature"`
		} `json:"quote"`
		PCRs map[int][]byte `json:"pcrs"`
	}{
		Quote: struct {
			Version   string `json:"version"`
			Quote     []byte `json:"quote"`
			Signature []byte `json:"signature"`
		}{
			Version:   fmt.Sprintf("%d", quote.Version),
			Quote:     quote.Quote,
			Signature: quote.Signature,
		},
		PCRs: selectedPCRValues,
	}

	// Encode the complete quote data for transmission
	quoteBytes, err := json.Marshal(quoteData)
	if err != nil {
		return nil, fmt.Errorf("marshaling quote data: %w", err)
	}

	return quoteBytes, nil
}

// publicKeyFromTPMTPublic converts a TPMTPublic to crypto.PublicKey
func publicKeyFromTPMTPublic(pub *tpm2.TPMTPublic) (crypto.PublicKey, error) {
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("reading RSA parameters: %w", err)
		}

		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return nil, fmt.Errorf("reading RSA unique: %w", err)
		}

		publicKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(rsaUnique.Buffer),
			E: int(rsaDetail.Exponent),
		}
		if publicKey.E == 0 {
			publicKey.E = 65537 // Default RSA exponent
		}

		return publicKey, nil

	case tpm2.TPMAlgECC:
		eccDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("reading ECC parameters: %w", err)
		}

		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("reading ECC unique: %w", err)
		}

		var curve elliptic.Curve
		switch eccDetail.CurveID {
		case tpm2.TPMECCNistP256:
			curve = elliptic.P256()
		case tpm2.TPMECCNistP384:
			curve = elliptic.P384()
		case tpm2.TPMECCNistP521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported ECC curve: %v", eccDetail.CurveID)
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
