/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package tpm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"
)

// PCRValues represents PCR measurements for attestation
type PCRValues struct {
	PCR0  []byte `json:"pcr0"`  // BIOS/UEFI measurements
	PCR7  []byte `json:"pcr7"`  // Secure Boot state
	PCR11 []byte `json:"pcr11"` // UKI measurements
}

// AttestationData is used to generate challanges from EKs
type AttestationData struct {
	EK       []byte     `json:"ek"`
	AK       []byte     `json:"ak"`                  // Raw AK public key bytes
	PCRs     *PCRValues `json:"pcrs,omitempty"`      // PCR measurements for boot state verification
	PCRQuote []byte     `json:"pcr_quote,omitempty"` // TPM-signed quote of PCR values
	Nonce    []byte     `json:"nonce,omitempty"`     // Server-provided nonce for freshness
}

// ChallengeRequest represents the initial request to KMS for a challenge
// Only includes what's needed for challenge generation and enrollment/verification
type ChallengeRequest struct {
	EK   []byte     `json:"ek"`   // Endorsement Key (TPM identity) - needed for challenge encryption
	AK   []byte     `json:"ak"`   // Raw AK public key bytes - needed for challenge binding
	PCRs *PCRValues `json:"pcrs"` // Current PCR measurements - needed for enrollment/verification
}

// ChallengeResponse represents the client's response to a challenge (LEGACY - maintains compatibility)
type ChallengeResponse struct {
	Secret []byte `json:"secret"` // Secret recovered from credential activation
}

// AttestationChallengeResponse represents the server's response containing challenge and nonce
type AttestationChallengeResponse struct {
	Challenge *attest.EncryptedCredential `json:"challenge"` // Credential activation challenge
	Nonce     []byte                      `json:"nonce"`     // Server-generated nonce for next request
	Enrolled  bool                        `json:"enrolled"`  // True if this was a new enrollment
}

// ProofRequest represents the client's proof of TPM ownership with anti-replay protection
type ProofRequest struct {
	Secret   []byte `json:"secret"`    // Secret recovered by activating the credential
	Nonce    []byte `json:"nonce"`     // Server nonce from previous response (anti-replay)
	PCRQuote []byte `json:"pcr_quote"` // Fresh TPM quote with nonce for cryptographic freshness proof
}

// ProofResponse represents the final response with the decryption passphrase
type ProofResponse struct {
	Passphrase []byte `json:"passphrase"` // The actual decryption passphrase
}

// DecodePubHash returns the public key from an attestation EK
func DecodePubHash(ek *attest.EK) (string, error) {
	data, err := pubBytes(ek)
	if err != nil {
		return "", err
	}
	pubHash := sha256.Sum256(data)
	hashEncoded := fmt.Sprintf("%x", pubHash)
	return hashEncoded, nil
}

func encodeEK(ek *attest.EK) ([]byte, error) {
	if ek.Certificate != nil {
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ek.Certificate.Raw,
		}), nil
	}

	data, err := pubBytes(ek)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	}), nil
}

func pubBytes(ek *attest.EK) ([]byte, error) {
	data, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return nil, fmt.Errorf("error marshaling ec public key: %v", err)
	}
	return data, nil
}

// GenerateNonce creates a cryptographically secure random nonce
// for use in remote attestation to ensure freshness
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 32) // 256-bit nonce
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return nonce, nil
}

// ParseAKBytes converts raw AK public key bytes into attest.AttestationParameters
// for use with the go-attestation library in challenge generation
func ParseAKBytes(akBytes []byte) (*attest.AttestationParameters, error) {
	if len(akBytes) == 0 {
		return nil, fmt.Errorf("empty AK bytes")
	}

	// The akBytes are in TPM2 public key format from tpm2.Public.Encode()
	// We can directly use them in AttestationParameters
	return &attest.AttestationParameters{
		Public: akBytes,
	}, nil
}
