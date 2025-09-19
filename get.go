package tpm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
)

// Authenticate will read from the passed channel, expecting a challenge from the
// attestation server, will compute a challenge response via the TPM using the passed
// Attestation Key (AK) and will send it back to the attestation server.
func Authenticate(akBytes []byte, channel io.ReadWriter, opts ...Option) error {
	c := newConfig()
	c.apply(opts...) //nolint:errcheck // Config validation happens later

	var challenge Challenge
	if err := json.NewDecoder(channel).Decode(&challenge); err != nil {
		return fmt.Errorf("unmarshalling Challenge: %w", err)
	}

	challengeResp, err := getChallengeResponse(c, challenge.EC, akBytes)
	if err != nil {
		return err
	}

	if err := json.NewEncoder(channel).Encode(challengeResp); err != nil {
		return fmt.Errorf("encoding ChallengeResponse: %w", err)
	}

	return nil
}

func writeRead(conn *websocket.Conn, input []byte) ([]byte, error) {
	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return nil, err
	}

	if _, err := writer.Write(input); err != nil {
		return nil, err
	}
	writer.Close() //nolint:errcheck // Cleanup operation
	_, reader, err := conn.NextReader()
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}

func getChallengeResponse(c *config, ec *attest.EncryptedCredential, aikBytes []byte) (*ChallengeResponse, error) {
	tpm, err := getTPM(c)
	if err != nil {
		return nil, fmt.Errorf("opening tpm: %w", err)
	}
	defer tpm.Close() //nolint:errcheck // Cleanup operation //nolint:errcheck // Cleanup operation

	aik, err := tpm.LoadAK(aikBytes)
	if err != nil {
		return nil, err
	}
	defer aik.Close(tpm) //nolint:errcheck // Cleanup operation

	secret, err := aik.ActivateCredential(tpm, *ec)
	if err != nil {
		return nil, fmt.Errorf("failed to activate credential: %w", err)
	}
	return &ChallengeResponse{
		Secret: secret,
	}, nil
}

// AttestationConnection returns a simple WebSocket connection for the new TPM attestation flow.
// Unlike Connection(), this function does not perform any authentication handshake - it just
// establishes the WebSocket connection and returns it for the caller to manage the protocol.
func AttestationConnection(url string, opts ...Option) (*websocket.Conn, error) {
	c := newConfig()
	c.apply(opts...) //nolint:errcheck // Config validation happens later

	header := c.header
	if c.header == nil {
		header = http.Header{}
	}

	dialer := websocket.DefaultDialer
	if len(c.cacerts) > 0 {
		pool := x509.NewCertPool()
		if c.systemfallback {
			systemPool, err := x509.SystemCertPool()
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
