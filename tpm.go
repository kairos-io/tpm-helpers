package tpm

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/kairos-io/tpm-helpers/backend"
	"github.com/pkg/errors"
)

// GenerateChallenge generates a challenge from attestation parameters and a public endorsed key
// This is the main function that should be used with go-attestation's native types
func GenerateChallenge(ek *attest.EK, akParams *attest.AttestationParameters) ([]byte, []byte, error) {
	fmt.Printf("Debug: GenerateChallenge called with EK.Public type: %T, AK Public length: %d\n", ek.Public, len(akParams.Public))

	ap := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ek.Public,
		AK:         *akParams, // Use the AttestationParameters directly
	}

	fmt.Printf("Debug: About to call ap.Generate() with TPMVersion: %v\n", ap.TPMVersion)
	secret, ec, err := ap.Generate()
	if err != nil {
		fmt.Printf("Debug: ap.Generate() failed with error: %v\n", err)
		return nil, nil, fmt.Errorf("generating challenge: %w", err)
	}
	fmt.Printf("Debug: ap.Generate() succeeded, secret length: %d\n", len(secret))

	challengeBytes, err := json.Marshal(Challenge{EC: ec})
	if err != nil {
		return nil, nil, fmt.Errorf("marshalling challenge: %w", err)
	}

	return secret, challengeBytes, nil
}

// ResolveToken is just syntax sugar around GetPubHash.
// If the token provided is in EK's form it just returns it, otherwise
// retrieves the pubhash
func ResolveToken(token string, opts ...Option) (bool, string, error) {
	if !strings.HasPrefix(token, "tpm://") {
		return false, token, nil
	}

	hash, err := GetPubHash(opts...)
	return true, hash, err
}

// GetPubHash returns the EK's pub hash
func GetPubHash(opts ...Option) (string, error) {
	c := newConfig()
	c.apply(opts...) //nolint:errcheck // Config validation happens later

	ek, err := getEK(c)
	if err != nil {
		return "", fmt.Errorf("getting EK: %w", err)
	}

	hash, err := DecodePubHash(ek)
	if err != nil {
		return "", fmt.Errorf("hashing EK: %w", err)
	}

	return hash, nil
}

func getTPM(c *config) (*attest.TPM, error) {

	cfg := &attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	}
	if c.commandChannel != nil {
		cfg.CommandChannel = c.commandChannel
	}

	if c.emulated {
		var sim *simulator.Simulator
		var err error
		if c.seed != 0 {
			sim, err = simulator.GetWithFixedSeedInsecure(c.seed)
		} else {
			sim, err = simulator.Get()
		}
		if err != nil {
			return nil, err
		}
		cfg.CommandChannel = backend.Fake(sim)
	}

	return attest.OpenTPM(cfg)

}

func getEK(c *config) (*attest.EK, error) {
	var err error

	tpm, err := getTPM(c)
	if err != nil {
		return nil, fmt.Errorf("opening tpm for decoding EK: %w", err)
	}
	defer tpm.Close() //nolint:errcheck // Cleanup operation //nolint:errcheck // Cleanup operation

	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("getting eks: %w", err)
	}

	if len(eks) == 0 {
		return nil, fmt.Errorf("failed to find EK")
	}

	return &eks[0], nil
}

// DecodeEK decodes EK pem bytes to attest.EK
func DecodeEK(pemBytes []byte) (*attest.EK, error) {
	block, _ := pem.Decode(pemBytes)

	if block == nil {
		return nil, errors.New("invalid pemBytes")
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
		}
		return &attest.EK{
			Certificate: cert,
			Public:      cert.PublicKey,
		}, nil

	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing ecdsa public key: %v", err)
		}

		return &attest.EK{
			Public: pub,
		}, nil
	}

	return nil, fmt.Errorf("invalid pem type: %s", block.Type)
}

// ValidateChallenge validates a challange against a secret
func ValidateChallenge(secret, resp []byte) error {
	var response ChallengeResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return fmt.Errorf("unmarshalling challenge response: %w", err)
	}
	if !bytes.Equal(secret, response.Secret) {
		return fmt.Errorf("invalid challenge response")
	}
	return nil
}
