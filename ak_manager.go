package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

// AKManager manages ephemeral Attestation Keys for TPM attestation.
// No persistent storage is required - AKs are created fresh for each attestation.
type AKManager struct {
	config *config
	tpm    *attest.TPM
	ak     *attest.AK
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

	return &AKManager{config: c, tpm: tpm}, nil
}

// Close closes the TPM session and cleans up resources
func (m *AKManager) Close() error {
	if m.tpm == nil {
		return nil
	}
	// Close AK first
	if m.ak != nil {
		_ = m.ak.Close(m.tpm)
		m.ak = nil
	}
	err := m.tpm.Close()
	m.tpm = nil
	return err
}

// GetAK returns the cached transient AK, creating it on first use
func (m *AKManager) GetAK() (*attest.AK, error) {
	if m.ak != nil {
		return m.ak, nil
	}
	if m.tpm == nil {
		return nil, fmt.Errorf("TPM session is not available")
	}
	ak, err := m.tpm.NewAK(nil)
	if err != nil {
		return nil, fmt.Errorf("creating transient AK: %w", err)
	}
	m.ak = ak
	return m.ak, nil
}

// AKParams returns the attestation parameters of the cached AK
func (m *AKManager) AKParams() (*attest.AttestationParameters, error) {
	ak, err := m.GetAK()
	if err != nil {
		return nil, err
	}
	params := ak.AttestationParameters()
	return &params, nil
}

// GetAKPublicKey returns the public key for the current transient AK
func (m *AKManager) GetAKPublicKey() (crypto.PublicKey, error) {
	ak, err := m.GetAK()
	if err != nil {
		return nil, err
	}

	// Get the public key from the cached AK's attestation parameters
	params := ak.AttestationParameters()
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](params.Public)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling public key: %w", err)
	}

	// Convert TPMTPublic to crypto.PublicKey
	return publicKeyFromTPMTPublic(pub)
}

// PerformAttestation performs a complete attestation flow using a transient AK
// ActivateCredential activates a credential using the cached AK
func (m *AKManager) ActivateCredential(challenge *attest.EncryptedCredential) ([]byte, error) {
	ak, err := m.GetAK()
	if err != nil {
		return nil, err
	}
	secret, err := ak.ActivateCredential(m.tpm, *challenge)
	if err != nil {
		return nil, fmt.Errorf("activating credential: %w", err)
	}
	return secret, nil
}

// GeneratePCRQuote generates a PCR quote using the cached AK
func (m *AKManager) GeneratePCRQuote(pcrs []int) ([]byte, error) {
	ak, err := m.GetAK()
	if err != nil {
		return nil, err
	}
	if len(pcrs) == 0 {
		return nil, fmt.Errorf("at least one PCR index must be specified")
	}
	for _, p := range pcrs {
		if p < 0 || p > 23 {
			return nil, fmt.Errorf("PCR index %d is out of range (0-23)", p)
		}
	}
	quote, err := ak.QuotePCRs(m.tpm, nil, attest.HashSHA256, pcrs)
	if err != nil {
		return nil, fmt.Errorf("generating PCR quote: %w", err)
	}
	allPCRs, err := m.tpm.PCRs(attest.HashSHA256)
	if err != nil {
		return nil, fmt.Errorf("reading PCRs: %w", err)
	}
	sel := make(map[int][]byte)
	for _, idx := range pcrs {
		if idx < len(allPCRs) {
			sel[idx] = allPCRs[idx].Digest
		}
	}
	payload := struct {
		Quote struct {
			Version   string `json:"version"`
			Quote     []byte `json:"quote"`
			Signature []byte `json:"signature"`
		} `json:"quote"`
		PCRs map[int][]byte `json:"pcrs"`
	}{}
	payload.Quote.Version = fmt.Sprintf("%d", quote.Version)
	payload.Quote.Quote = quote.Quote
	payload.Quote.Signature = quote.Signature
	payload.PCRs = sel
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling quote data: %w", err)
	}
	return out, nil
}

// VerifyPCRQuote verifies a PCR quote and ensures PCR values are consistent with the quote
// Returns the verified PCR values.
func VerifyPCRQuote(quoteBytes []byte, akPublic crypto.PublicKey) (map[int][]byte, error) {
	if len(quoteBytes) == 0 {
		return nil, fmt.Errorf("empty quote data")
	}

	// Parse the quote structure
	var quoteData struct {
		Quote struct {
			Version   string `json:"version"`
			Quote     []byte `json:"quote"`
			Signature []byte `json:"signature"`
		} `json:"quote"`
		PCRs map[int][]byte `json:"pcrs"`
	}

	if err := json.Unmarshal(quoteBytes, &quoteData); err != nil {
		return nil, fmt.Errorf("unmarshaling quote data: %w", err)
	}

	// Verify the quote signature using the AK public key
	if err := verifyQuoteSignature(quoteData.Quote.Quote, quoteData.Quote.Signature, akPublic); err != nil {
		return nil, fmt.Errorf("quote signature verification failed: %w", err)
	}

	// Verify that the provided PCRs are consistent with the quote
	if err := verifyPCRsAgainstQuote(quoteData.Quote.Quote, quoteData.PCRs); err != nil {
		return nil, fmt.Errorf("PCR verification against quote failed: %w", err)
	}

	// Return the verified PCR values
	return quoteData.PCRs, nil
}

// verifyQuoteSignature verifies the TPM quote signature using the AK public key
func verifyQuoteSignature(quote, signature []byte, akPublic crypto.PublicKey) error {
	if len(quote) == 0 || len(signature) == 0 {
		return fmt.Errorf("empty quote or signature")
	}

	// Parse the TPM signature structure
	tpmSig, err := tpm2.Unmarshal[tpm2.TPMTSignature](signature)
	if err != nil {
		return fmt.Errorf("unmarshaling TPM signature: %w", err)
	}

	// Hash the quote data using the hash algorithm from the signature
	hash := sha256.Sum256(quote)

	// Verify the signature based on the algorithm
	switch tpmSig.SigAlg {
	case tpm2.TPMAlgRSASSA, tpm2.TPMAlgRSAPSS:
		rsaSig, err := tpmSig.Signature.RSASSA()
		if err != nil {
			return fmt.Errorf("getting RSA signature: %w", err)
		}

		rsaPub, ok := akPublic.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("AK public key is not RSA")
		}

		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], rsaSig.Sig.Buffer)

	case tpm2.TPMAlgECDSA:
		eccSig, err := tpmSig.Signature.ECDSA()
		if err != nil {
			return fmt.Errorf("getting ECDSA signature: %w", err)
		}

		eccPub, ok := akPublic.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("AK public key is not ECDSA")
		}

		r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
		s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)

		if !ecdsa.Verify(eccPub, hash[:], r, s) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported signature algorithm: %v", tpmSig.SigAlg)
	}
}

// verifyPCRsAgainstQuote verifies that the provided PCRs are consistent with the TPM quote
func verifyPCRsAgainstQuote(quote []byte, providedPCRs map[int][]byte) error {
	// Parse the TPM quote structure using modern go-tpm API
	attestData, err := tpm2.Unmarshal[tpm2.TPMSAttest](quote)
	if err != nil {
		return fmt.Errorf("decoding attestation data: %w", err)
	}

	// Check if this is a quote attestation
	if attestData.Type != tpm2.TPMSTAttestQuote {
		return fmt.Errorf("not a quote attestation, got type: %v", attestData.Type)
	}

	// Get the quote info from the Attested union
	quoteInfo, err := attestData.Attested.Quote()
	if err != nil {
		return fmt.Errorf("getting quote info from attestation: %w", err)
	}

	// Extract PCR selection from the quote info
	selectedPCRs := make(map[int]bool)
	if len(quoteInfo.PCRSelect.PCRSelections) > 0 {
		// Parse the PCR selection to get the selected PCRs
		for _, pcrSelection := range quoteInfo.PCRSelect.PCRSelections {
			// Extract PCR selection from the bitmap
			for i := 0; i < len(pcrSelection.PCRSelect); i++ {
				byteVal := pcrSelection.PCRSelect[i]
				for bit := 0; bit < 8; bit++ {
					if byteVal&(1<<bit) != 0 {
						pcrIndex := i*8 + bit
						selectedPCRs[pcrIndex] = true
					}
				}
			}
		}
	}

	// Verify that all provided PCRs were selected in the quote
	for pcrIndex := range providedPCRs {
		if !selectedPCRs[pcrIndex] {
			return fmt.Errorf("PCR %d was provided but not selected in the quote", pcrIndex)
		}
	}

	// Verify that all selected PCRs were provided
	for pcrIndex := range selectedPCRs {
		if _, exists := providedPCRs[pcrIndex]; !exists {
			return fmt.Errorf("PCR %d was selected in the quote but not provided", pcrIndex)
		}
	}

	// Verify that the provided PCRs, when hashed, match the quote digest
	if err := verifyPCRDigest(quoteInfo.PCRDigest.Buffer, providedPCRs, selectedPCRs); err != nil {
		return fmt.Errorf("PCR digest verification failed: %w", err)
	}

	return nil
}

// verifyPCRDigest verifies that the provided PCRs, when hashed, match the quote digest
func verifyPCRDigest(quoteDigest []byte, providedPCRs map[int][]byte, selectedPCRs map[int]bool) error {
	// Calculate the digest of the provided PCRs in the same order as the TPM
	// The TPM calculates the digest by concatenating the PCR values in order
	var pcrData []byte
	for pcrIndex := 0; pcrIndex < 24; pcrIndex++ { // TPM has 24 PCRs (0-23)
		if selectedPCRs[pcrIndex] {
			if pcrValue, exists := providedPCRs[pcrIndex]; exists {
				pcrData = append(pcrData, pcrValue...)
			} else {
				return fmt.Errorf("PCR %d was selected but not provided", pcrIndex)
			}
		}
	}

	// Calculate the hash of the PCR data
	hash := sha256.Sum256(pcrData)

	// Compare with the quote digest
	if len(quoteDigest) != len(hash) {
		return fmt.Errorf("PCR digest length mismatch: expected %d bytes, got %d bytes",
			len(quoteDigest), len(hash))
	}

	for i, b := range quoteDigest {
		if b != hash[i] {
			return fmt.Errorf("PCR digest mismatch at byte %d", i)
		}
	}

	return nil
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

// GetAKPublicKeyBytes returns the raw AK public key bytes for transmission
func (m *AKManager) GetAKPublicKeyBytes() ([]byte, error) {
	ak, err := m.GetAK()
	if err != nil {
		return nil, err
	}
	params := ak.AttestationParameters()
	return params.Public, nil
}

// GetAttestationData returns the EK and AttestationParameters for challenge generation
// This provides go-attestation native types for transient AK attestation
func (m *AKManager) GetAttestationData() (*attest.EK, *attest.AttestationParameters, error) {
	// Get EK from TPM
	ek, err := m.GetEK()
	if err != nil {
		return nil, nil, fmt.Errorf("getting EK: %w", err)
	}

	// Get AK AttestationParameters from the transient AK
	ak, err := m.GetAK()
	if err != nil {
		return nil, nil, err
	}
	params := ak.AttestationParameters()

	return ek, &params, nil
}

// CreateProofRequest creates a proof request with the activated credential secret and PCR quote
// This is the main method that should be used for complete attestation proof
func (m *AKManager) CreateProofRequest(challenge *AttestationChallengeResponse, pcrs []int) (*ProofRequest, error) {
	// Activate the credential to get the secret
	ak, err := m.GetAK()
	if err != nil {
		return nil, err
	}
	secret, err := ak.ActivateCredential(m.tpm, *challenge.Challenge)
	if err != nil {
		return nil, fmt.Errorf("activating credential: %w", err)
	}

	// Generate a fresh PCR quote for cryptographic proof using requested PCRs
	quote, err := m.GeneratePCRQuote(pcrs)
	if err != nil {
		return nil, fmt.Errorf("generating quote: %w", err)
	}

	return &ProofRequest{
		Secret:   secret,
		PCRQuote: quote, // Cryptographic proof of TPM state
	}, nil
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
