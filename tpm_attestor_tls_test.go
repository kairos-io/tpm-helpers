package tpm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// nameOnlyCert returns a self-signed certificate valid for name and nothing
// else, so it carries no IP SAN, plus its PEM encoding to pin as the CA.
func nameOnlyCert(name string) (tls.Certificate, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).ToNot(HaveOccurred())

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

var _ = Describe("AttestationConnection TLS server name", func() {
	const name = "mychallenger.local"
	var (
		server *httptest.Server
		caPEM  []byte
		ipURL  string
	)

	BeforeEach(func() {
		var cert tls.Certificate
		cert, caPEM = nameOnlyCert(name)

		server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()                                                                                        //nolint:errcheck // Test cleanup
			conn.WriteJSON(map[string]string{"host": r.Host})                                                         //nolint:errcheck // Test cleanup
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")) //nolint:errcheck // Test cleanup
		}))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		server.StartTLS()
		DeferCleanup(server.Close)

		// The server is dialed by address, the way a caller does after
		// resolving the name itself (an mDNS lookup, for instance).
		ipURL = server.URL + "/test"
		Expect(ipURL).To(HavePrefix("https://127.0.0.1:"))
	})

	It("rejects a certificate for the name when only the address is known", func() {
		_, err := AttestationConnection(ipURL, Emulated, WithSeed(1), WithCAs(caPEM))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("127.0.0.1"))
	})

	It("verifies the certificate against the name in the Host header", func() {
		port := ipURL[strings.LastIndex(ipURL, ":")+1 : strings.LastIndex(ipURL, "/")]
		host := name + ":" + port

		conn, err := AttestationConnection(ipURL, Emulated, WithSeed(1), WithCAs(caPEM), WithAdditionalHeader("Host", host))
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close() //nolint:errcheck // Test cleanup

		result := map[string]string{}
		Expect(conn.ReadJSON(&result)).To(Succeed())
		Expect(result["host"]).To(Equal(host))
	})
})
