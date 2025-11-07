package tpm

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/kairos-io/tpm-helpers/backend"
	"github.com/pkg/errors"
)

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

	// Priority: commandChannel > device > emulated
	if c.commandChannel != nil {
		cfg.CommandChannel = c.commandChannel
	} else if c.device != "" {
		// Open the specified TPM device and create a command channel from it
		tpmTransport, err := transport.OpenTPM(c.device)
		if err != nil {
			return nil, fmt.Errorf("opening TPM device %s: %w", c.device, err)
		}
		cfg.CommandChannel = backend.FromTransport(tpmTransport)
	} else if c.emulated {
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
