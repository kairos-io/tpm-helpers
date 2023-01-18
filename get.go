package tpm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
)

// GetAuthToken generates an authentication token from the host TPM.
// It will return the token as a string and the generated AK that should
// be saved by the caller for later Authentication.
func GetAuthToken(opts ...Option) (string, []byte, error) {
	c := newConfig()
	c.apply(opts...)

	attestationData, akBytes, err := getAttestationData(c)
	if err != nil {
		return "", nil, err
	}

	token, err := getToken(attestationData)
	if err != nil {
		return "", nil, err
	}

	return token, akBytes, err
}

// Authenticate will read from the passed channel, expecting a challenge from the
// attestation server, will compute a challenge response via the TPM using the passed
// Attestation Key (AK) and will send it back to the attestation server.
func Authenticate(akBytes []byte, channel io.ReadWriter, opts ...Option) error {
	c := newConfig()
	c.apply(opts...)

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

func AuthRequest(r *http.Request, conn *websocket.Conn) error {
	token := r.Header.Get("Authorization")
	ek, at, err := GetAttestationData(token)
	if err != nil {
		return err
	}
	secret, challenge, err := GenerateChallenge(ek, at)
	if err != nil {
		return err
	}

	resp, err := writeRead(conn, challenge)
	if err != nil {
		return err
	}

	if err := ValidateChallenge(secret, resp); err != nil {
		return fmt.Errorf("error validating challenge: %w (response: %s)", err, string(resp))
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
	writer.Close()
	_, reader, err := conn.NextReader()
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(reader)
}

// Get retrieves a message from a remote ws server after
// a successfully process of the TPM challenge
func Get(url string, opts ...Option) ([]byte, error) {
	conn, err := Connection(url, opts...)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, msg, err := conn.NextReader()
	if err != nil {
		return nil, fmt.Errorf("reading payload from tpm get: %w", err)
	}

	return ioutil.ReadAll(msg)
}

// Connection returns a connection to the endpoint which suathenticated already.
// The server side needs to call AuthRequest on the http request in order to authenticate and refuse connections
func Connection(url string, opts ...Option) (*websocket.Conn, error) {
	c := newConfig()
	c.apply(opts...)

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

	attestationData, aikBytes, err := getAttestationData(c)
	if err != nil {
		return nil, err
	}

	// hash, err := GetPubHash(opts...)
	// if err != nil {
	// 	return nil, err
	// }

	token, err := getToken(attestationData)
	if err != nil {
		return nil, err
	}

	header.Add("Authorization", token)
	for k, v := range c.headers {
		header.Add(k, v)
	}

	wsURL := strings.Replace(url, "http", "ws", 1)
	//logrus.Infof("Using TPMHash %s to dial %s", hash, wsURL)
	conn, resp, err := dialer.Dial(wsURL, header)
	if err != nil {
		if resp != nil {
			if resp.StatusCode == http.StatusUnauthorized {
				data, err := ioutil.ReadAll(resp.Body)
				if err == nil {
					return nil, errors.New(string(data))
				}
			} else {
				return nil, fmt.Errorf("%w (Status: %s)", err, resp.Status)
			}
		}
		return nil, err
	}

	_, msg, err := conn.NextReader()
	if err != nil {
		return nil, fmt.Errorf("reading challenge: %w", err)
	}

	var challenge Challenge
	if err := json.NewDecoder(msg).Decode(&challenge); err != nil {
		return nil, fmt.Errorf("unmarshaling Challenge: %w", err)
	}

	challengeResp, err := getChallengeResponse(c, challenge.EC, aikBytes)
	if err != nil {
		return nil, err
	}

	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return nil, err
	}

	if err := json.NewEncoder(writer).Encode(challengeResp); err != nil {
		return nil, fmt.Errorf("encoding ChallengeResponse: %w", err)
	}

	writer.Close()

	return conn, nil
}

func getChallengeResponse(c *config, ec *attest.EncryptedCredential, aikBytes []byte) (*ChallengeResponse, error) {
	tpm, err := getTPM(c)
	if err != nil {
		return nil, fmt.Errorf("opening tpm: %w", err)
	}
	defer tpm.Close()

	aik, err := tpm.LoadAK(aikBytes)
	if err != nil {
		return nil, err
	}
	defer aik.Close(tpm)

	secret, err := aik.ActivateCredential(tpm, *ec)
	if err != nil {
		return nil, fmt.Errorf("failed to activate credential: %w", err)
	}
	return &ChallengeResponse{
		Secret: secret,
	}, nil
}
