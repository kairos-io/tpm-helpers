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
	"crypto/sha256"
	"crypto/tls"
	stdx509 "crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
)

// ChallengeResponse represents the client's response to a challenge
type ChallengeResponse struct {
	Secret []byte `json:"secret"` // Secret recovered from credential activation
}

// AttestationChallengeResponse represents the server's response containing challenge
type AttestationChallengeResponse struct {
	Challenge *attest.EncryptedCredential `json:"challenge"` // Credential activation challenge
}

// ProofRequest represents the client's proof of TPM ownership
type ProofRequest struct {
	Secret   []byte `json:"secret"`    // Secret recovered by activating the credential
	PCRQuote []byte `json:"pcr_quote"` // Fresh TPM quote for cryptographic proof
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

func pubBytes(ek *attest.EK) ([]byte, error) {
	data, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return nil, fmt.Errorf("error marshaling ec public key: %v", err)
	}
	return data, nil
}

// AttestationConnection returns a simple WebSocket connection for the new TPM attestation flow.
func AttestationConnection(url string, opts ...Option) (*websocket.Conn, error) {
	c := newConfig()
	c.apply(opts...) //nolint:errcheck // Config validation happens later

	header := c.header
	if c.header == nil {
		header = http.Header{}
	}

	dialer := websocket.DefaultDialer
	if len(c.cacerts) > 0 {
		pool := stdx509.NewCertPool()
		if c.systemfallback {
			systemPool, err := stdx509.SystemCertPool()
			if err != nil {
				return nil, err
			}
			pool = systemPool
		}

		pool.AppendCertsFromPEM(c.cacerts)
		dialer = &websocket.Dialer{
			Proxy:            http.ProxyFromEnvironment,
			HandshakeTimeout: 45 * time.Second,
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
			},
		}
	}

	// Add any additional headers
	for k, v := range c.headers {
		header.Add(k, v)
	}

	wsURL := strings.Replace(url, "http", "ws", 1)
	conn, resp, err := dialer.Dial(wsURL, header)
	if err != nil {
		if resp != nil {
			if resp.StatusCode == http.StatusUnauthorized {
				data, err := io.ReadAll(resp.Body)
				if err == nil {
					return nil, errors.New(string(data))
				}
			} else {
				return nil, fmt.Errorf("%w (Status: %s)", err, resp.Status)
			}
		}
		return nil, err
	}

	return conn, nil
}
