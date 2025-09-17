package tpm

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/kairos-io/tpm-helpers/backend"
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

// AKBlob represents the TPM-encrypted AK blob stored on disk
type AKBlob struct {
	Private []byte `json:"private"` // TPM-encrypted private key blob
	Public  []byte `json:"public"`  // Public key data
}

// AKInfo holds information about a loaded Attestation Key
type AKInfo struct {
	Handle         tpmutil.Handle   // Transient TPM handle (after loading)
	PublicKey      crypto.PublicKey // Public key extracted from AK
	PublicKeyBytes []byte           // Raw public key bytes for transmission
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
	c.apply(opts...)

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
		// Load existing AK and return public key
		akInfo, err := m.LoadAK()
		if err != nil {
			return nil, fmt.Errorf("loading existing AK: %w", err)
		}
		defer m.CloseAK(akInfo.Handle)
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
	// Load AK info from blob
	akInfo, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer m.CloseAK(akInfo.Handle)

	return akInfo.PublicKey, nil
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

// createAndStoreAK creates a new AK and stores the TPM-encrypted blob to file
func (m *AKManager) createAndStoreAK() ([]byte, error) {
	// Open TPM
	rwc, err := getRawTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer rwc.Close()

	// Create Storage Root Key (SRK) as parent for the AK
	srkTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	srkHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("creating SRK: %w", err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	// Create AK template
	akTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagSign,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSAPSS,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	// Create the AK under the SRK
	akPrivate, akPublic, _, _, _, err := tpm2.CreateKey(rwc, srkHandle, tpm2.PCRSelection{}, "", "", akTemplate)
	if err != nil {
		return nil, fmt.Errorf("creating AK: %w", err)
	}

	// Load the AK to get the public key
	akHandle, _, err := tpm2.Load(rwc, srkHandle, "", akPublic, akPrivate)
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer tpm2.FlushContext(rwc, akHandle)

	// Get public key for return
	pub, _, _, err := tpm2.ReadPublic(rwc, akHandle)
	if err != nil {
		return nil, fmt.Errorf("reading AK public key: %w", err)
	}

	// Extract public key bytes
	publicKeyBytes, err := pub.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}

	// Create the AK blob structure containing private and public parts
	akBlob := AKBlob{
		Private: akPrivate,
		Public:  akPublic,
	}

	// Store the TPM-encrypted blob to file
	if err := m.saveAKBlob(&akBlob); err != nil {
		return nil, fmt.Errorf("saving AK blob: %w", err)
	}

	return publicKeyBytes, nil
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

// LoadAK loads the AK from the blob file into a transient TPM handle
func (m *AKManager) LoadAK() (*AKInfo, error) {
	// Load AK blob from file
	blob, err := m.loadAKBlob()
	if err != nil {
		return nil, fmt.Errorf("loading AK blob: %w", err)
	}

	// Open TPM
	rwc, err := getRawTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer rwc.Close()

	// Create SRK (same as during creation)
	srkTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	srkHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("creating SRK: %w", err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	// Load the AK from the blob into a transient handle
	akHandle, _, err := tpm2.Load(rwc, srkHandle, "", blob.Public, blob.Private)
	if err != nil {
		return nil, fmt.Errorf("loading AK from blob: %w", err)
	}
	// Note: Don't defer close here - caller will manage the handle

	// Get public key
	pub, _, _, err := tpm2.ReadPublic(rwc, akHandle)
	if err != nil {
		tpm2.FlushContext(rwc, akHandle)
		return nil, fmt.Errorf("reading AK public key: %w", err)
	}

	publicKey, err := pub.Key()
	if err != nil {
		tpm2.FlushContext(rwc, akHandle)
		return nil, fmt.Errorf("extracting public key: %w", err)
	}

	publicKeyBytes, err := pub.Encode()
	if err != nil {
		tpm2.FlushContext(rwc, akHandle)
		return nil, fmt.Errorf("encoding public key: %w", err)
	}

	return &AKInfo{
		Handle:         akHandle,
		PublicKey:      publicKey,
		PublicKeyBytes: publicKeyBytes,
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

// CloseAK closes the transient AK handle in the TPM
func (m *AKManager) CloseAK(handle tpmutil.Handle) error {
	rwc, err := getRawTPM(m.config)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer rwc.Close()

	return tpm2.FlushContext(rwc, handle)
}

// GetChallengeRequest creates the initial challenge request to KMS
// This works for both first-time enrollment and subsequent verification
func (m *AKManager) GetChallengeRequest() (*ChallengeRequest, error) {
	// Get EK using existing function
	ek, err := getEK(m.config)
	if err != nil {
		return nil, fmt.Errorf("getting EK: %w", err)
	}

	// Encode EK using existing function
	ekBytes, err := encodeEK(ek)
	if err != nil {
		return nil, fmt.Errorf("encoding EK: %w", err)
	}

	// Get AK attestation parameters from our persisted AK
	akInfo, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer m.CloseAK(akInfo.Handle)

	// Create attestation parameters from our loaded AK
	attestParams := &attest.AttestationParameters{
		Public: akInfo.PublicKeyBytes,
	}

	// Read current PCR values for enrollment/verification
	pcrValues, err := m.readPCRValues()
	if err != nil {
		return nil, fmt.Errorf("reading PCR values: %w", err)
	}

	return &ChallengeRequest{
		EK:   ekBytes,      // Needed for challenge encryption
		AK:   attestParams, // Needed for challenge binding
		PCRs: pcrValues,    // Needed for enrollment/verification (but not challenge generation)
	}, nil
}

// CreateProofRequest creates a proof request with the activated credential secret and nonce-based quote
func (m *AKManager) CreateProofRequest(challengeResp *AttestationChallengeResponse) (*ProofRequest, error) {
	// Activate the credential to get the secret
	challenge := &Challenge{EC: challengeResp.Challenge}
	secret, err := m.ActivateCredential(challenge)
	if err != nil {
		return nil, fmt.Errorf("activating credential: %w", err)
	}

	// Generate a fresh PCR quote with the server's nonce for cryptographic freshness proof
	quote, err := m.generatePCRQuote(challengeResp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("generating nonce-based quote: %w", err)
	}

	return &ProofRequest{
		Secret:   secret,
		Nonce:    challengeResp.Nonce, // Include server's nonce for anti-replay
		PCRQuote: quote,               // Cryptographic proof that includes the nonce
	}, nil
}

// Challenge represents a simple credential activation challenge
type Challenge struct {
	EC *attest.EncryptedCredential
}

// ActivateCredential decrypts a credential blob using the loaded AK and EK
// Takes the challenge received from server and returns the recovered secret
func (m *AKManager) ActivateCredential(challenge *Challenge) ([]byte, error) {
	// Open raw TPM for go-tpm operations
	rwc, err := getRawTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer rwc.Close()

	// Load our actual persistent AK
	akInfo, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer m.CloseAK(akInfo.Handle)

	// Load EK for activation
	ekHandle, err := m.loadEKHandle(rwc)
	if err != nil {
		return nil, fmt.Errorf("loading EK handle: %w", err)
	}
	defer tpm2.FlushContext(rwc, ekHandle)

	// Use go-tpm ActivateCredential directly
	secret, err := tpm2.ActivateCredential(
		rwc,
		akInfo.Handle,           // activeHandle (our loaded AK)
		ekHandle,                // keyHandle (EK for decryption)
		"",                      // activePassword (empty)
		"",                      // protectorPassword (empty)
		challenge.EC.Credential, // credBlob
		challenge.EC.Secret,     // secret
	)
	if err != nil {
		return nil, fmt.Errorf("activating credential with TPM: %w", err)
	}

	return secret, nil
}

// loadEKHandle loads the EK and returns its handle for activation
func (m *AKManager) loadEKHandle(rwc io.ReadWriteCloser) (tpmutil.Handle, error) {
	// EK template for RSA 2048 - same as in GetEnrollmentPayload logic
	ekTemplate := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagAdminWithPolicy |
			tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: DefaultEKAuthPolicy,
		RSAParameters: &tpm2.RSAParams{
			KeyBits: 2048,
		},
	}

	// Create EK primary key
	ekHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", ekTemplate)
	if err != nil {
		return 0, fmt.Errorf("creating EK primary: %w", err)
	}

	return ekHandle, nil
}

// readPCRValues reads PCR values 0, 7, and 11 from the TPM
func (m *AKManager) readPCRValues() (*PCRValues, error) {
	rwc, err := getRawTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer rwc.Close()

	// Read PCRs using ReadPCRs function which can read multiple PCRs at once
	pcrValues, err := tpm2.ReadPCRs(rwc, tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{0, 7, 11},
	})
	if err != nil {
		return nil, fmt.Errorf("reading PCRs: %w", err)
	}

	// Extract individual PCR values
	pcr0, ok := pcrValues[0]
	if !ok {
		return nil, fmt.Errorf("PCR 0 not found in response")
	}

	pcr7, ok := pcrValues[7]
	if !ok {
		return nil, fmt.Errorf("PCR 7 not found in response")
	}

	pcr11, ok := pcrValues[11]
	if !ok {
		return nil, fmt.Errorf("PCR 11 not found in response")
	}

	return &PCRValues{
		PCR0:  pcr0,
		PCR7:  pcr7,
		PCR11: pcr11,
	}, nil
}

// generatePCRQuote generates a TPM quote (signed attestation) of PCR values using the AK
func (m *AKManager) generatePCRQuote(nonce []byte) ([]byte, error) {
	rwc, err := getRawTPM(m.config)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer rwc.Close()

	// Load AK for signing the quote
	akInfo, err := m.LoadAK()
	if err != nil {
		return nil, fmt.Errorf("loading AK: %w", err)
	}
	defer m.CloseAK(akInfo.Handle)

	// Define PCR selection for quote (PCRs 0, 7, 11)
	pcrSelection := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{0, 7, 11},
	}

	// Generate quote - this cryptographically signs the PCR values with the AK
	attestation, signature, err := tpm2.Quote(
		rwc,
		akInfo.Handle,
		"", // password (empty)
		"", // qualifyingData (empty)
		nonce,
		pcrSelection,
		tpm2.AlgNull, // sigAlg (use key's default)
	)
	if err != nil {
		return nil, fmt.Errorf("generating TPM quote: %w", err)
	}

	// Encode signature to bytes for transmission
	sigBytes, err := signature.Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding signature: %w", err)
	}

	// Combine attestation and signature into a single blob
	// In a real implementation, you might want a more structured format
	quote := append(attestation, sigBytes...)
	return quote, nil
}

// getRawTPM returns a raw TPM connection respecting the emulated/real configuration
func getRawTPM(c *config) (io.ReadWriteCloser, error) {
	if c.emulated {
		var sim *simulator.Simulator
		var err error
		if c.seed != 0 {
			sim, err = simulator.GetWithFixedSeedInsecure(c.seed)
		} else {
			sim, err = simulator.Get()
		}
		if err != nil {
			return nil, fmt.Errorf("getting simulator: %w", err)
		}
		return backend.Fake(sim), nil
	}

	// Use real TPM
	return tpm2.OpenTPM()
}
