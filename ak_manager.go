package tpm

import (
	"crypto"
	"encoding/json"
	"fmt"
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

// AKBlob represents the AK data stored on disk
type AKBlob struct {
	AKBytes           []byte `json:"ak_bytes"`           // Marshaled go-attestation AK
	AttestationParams []byte `json:"attestation_params"` // Serialized AttestationParameters from go-attestation
}

// AKInfo holds information about a loaded Attestation Key
type AKInfo struct {
	PublicKeyBytes    []byte                        // Raw AK public key bytes for transmission
	AttestationParams *attest.AttestationParameters // Complete AttestationParameters from go-attestation
	AKBytes           []byte                        // Marshaled AK for later loading
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
		akInfo, err := m.LoadAK()
		if err != nil {
			return nil, fmt.Errorf("failed to load existing AK blob file (this may indicate corruption or version mismatch). Please verify the file or remove it manually and retry. File: %s, Error: %w", m.akBlobFile, err)
		}

		return akInfo.PublicKeyBytes, nil
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
	akInfo, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}

	ak, err := tpm.LoadAK(akInfo.AKBytes)
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer ak.Close(tpm) //nolint:errcheck

	// Get the public key from the AK's attestation parameters
	params := ak.AttestationParameters()
	pub, err := tpm2.DecodePublic(params.Public)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}

	return pub.Key()
}

// ReadAKInfo reads AK information by loading from blob
func (m *AKManager) ReadAKInfo() (*AKInfo, error) {
	return m.LoadAK()
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

	// Get AttestationParameters (same as legacy flow)
	params := ak.AttestationParameters()

	// Marshal the AK for storage (same as legacy flow)
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
	akBlob := AKBlob{
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
func (m *AKManager) saveAKBlob(blob *AKBlob) error {
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

// LoadAK loads the AK from the blob file and deserializes the AttestationParameters
func (m *AKManager) LoadAK() (*AKInfo, error) {
	// Load AK blob from file
	blob, err := m.loadAKBlob()
	if err != nil {
		return nil, fmt.Errorf("loading AK blob: %w", err)
	}

	// Check if AttestationParams is empty
	if len(blob.AttestationParams) == 0 {
		return nil, fmt.Errorf("AttestationParams field is empty in AK blob")
	}

	// Deserialize the AttestationParameters
	var params attest.AttestationParameters
	if err := json.Unmarshal(blob.AttestationParams, &params); err != nil {
		return nil, fmt.Errorf("unmarshaling attestation parameters: %w", err)
	}

	return &AKInfo{
		PublicKeyBytes:    params.Public, // Use the exact same bytes as legacy flow
		AttestationParams: &params,       // Complete AttestationParameters for challenge generation
		AKBytes:           blob.AKBytes,  // Marshaled AK for activation
	}, nil
}

// loadAKBlob loads the AK blob from the configured file
func (m *AKManager) loadAKBlob() (*AKBlob, error) {
	data, err := os.ReadFile(m.akBlobFile)
	if err != nil {
		return nil, fmt.Errorf("reading AK blob file: %w", err)
	}

	var blob AKBlob
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
	akInfo, err := m.LoadAK()
	if err != nil {
		return nil, nil, fmt.Errorf("loading AK: %w", err)
	}

	return ek, akInfo.AttestationParams, nil
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
	quote, err := m.generatePCRQuote()
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
	akInfo, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK info: %w", err)
	}

	// Load the marshaled AK using go-attestation
	ak, err := tpm.LoadAK(akInfo.AKBytes)
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

// readPCRValues reads PCR values 0, 7, and 11 from the TPM
func (m *AKManager) readPCRValues() (*PCRValues, error) {
	// Open TPM using go-attestation
	tpm, err := getTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close() //nolint:errcheck

	// Read PCRs using go-attestation
	pcrs, err := tpm.PCRs(attest.HashSHA256)
	if err != nil {
		return nil, fmt.Errorf("reading PCRs: %w", err)
	}

	// Extract individual PCR values
	if len(pcrs) <= 11 {
		return nil, fmt.Errorf("insufficient PCRs available")
	}

	return &PCRValues{
		PCR0:  pcrs[0].Digest,
		PCR7:  pcrs[7].Digest,
		PCR11: pcrs[11].Digest,
	}, nil
}

// generatePCRQuote generates a TPM quote (signed attestation) of PCR values using the AK
func (m *AKManager) generatePCRQuote() ([]byte, error) {
	// Open TPM using go-attestation
	tpm, err := getTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close() //nolint:errcheck

	// Load AK using go-attestation
	akInfo, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK info: %w", err)
	}

	ak, err := tpm.LoadAK(akInfo.AKBytes)
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer ak.Close(tpm) //nolint:errcheck

	// Generate quote using go-attestation with empty qualifying data
	quote, err := ak.Quote(tpm, nil, attest.HashSHA256)
	if err != nil {
		return nil, fmt.Errorf("generating PCR quote: %w", err)
	}

	// Encode the quote for transmission
	quoteBytes, err := json.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("marshaling quote: %w", err)
	}

	return quoteBytes, nil
}
