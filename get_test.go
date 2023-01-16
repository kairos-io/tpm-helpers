package tpm_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func writeRead(conn *websocket.Conn, input []byte) ([]byte, error) {
	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return nil, err
	}

	if _, err := writer.Write(input); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	_, reader, err := conn.NextReader()
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(reader)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// Mimics a WS server which accepts TPM Bearer token
func WSServer(ctx context.Context) {
	s := http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m := http.NewServeMux()
	m.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity

		for {

			token := r.Header.Get("Authorization")
			awesome := r.Header.Get("awesome")
			ek, at, err := GetAttestationData(token)
			if err != nil {
				fmt.Println("error", err.Error())
				return
			}

			secret, challenge, err := GenerateChallenge(ek, at)
			if err != nil {
				fmt.Println("error", err.Error())
				return
			}

			resp, _ := writeRead(conn, challenge)

			if err := ValidateChallenge(secret, resp); err != nil {
				fmt.Println("error validating challenge", err.Error())
				return
			}

			writer, _ := conn.NextWriter(websocket.BinaryMessage)
			json.NewEncoder(writer).Encode(map[string]string{"foo": "bar", "header": awesome})
		}
	})

	s.Handler = m

	go s.ListenAndServe()
	go func() {
		<-ctx.Done()
		s.Shutdown(ctx)
	}()
}

var _ = Describe("GET", func() {
	Context("challenges", func() {
		It("fails for permissions", func() {
			_, err := Get("http://localhost:8080/test")
			Expect(err).To(HaveOccurred())
		})
		It("gets pubhash", func() {

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			WSServer(ctx)

			msg, err := Get("http://localhost:8080/test", Emulated, WithSeed(1), WithAdditionalHeader("awesome", "content"))
			result := map[string]interface{}{}
			json.Unmarshal(msg, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal(map[string]interface{}{"foo": "bar", "header": "content"}))
		})
	})
})

// This test is meant to be running manually against a
// reg. server with a valid cert.
var _ = Describe("GET", func() {
	Context("challenges with a remote endpoint", func() {
		regUrl := os.Getenv("REG_URL")

		expectedMatches := ContainElement("ros-node-{{ trunc 4 .MachineID }}")
		BeforeEach(func() {
			if regUrl == "" {
				Skip("No remote url passed, skipping suite")
			}
		})

		It("gets pubhash from remote with a public signed CA", func() {
			msg, err := Get(regUrl, Emulated, WithSeed(1))
			result := map[string]interface{}{}
			json.Unmarshal(msg, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(expectedMatches)
		})

		It("it fails if we specify a custom CA (invalid)", func() {
			msg, err := Get(regUrl, Emulated, WithSeed(1), WithCAs([]byte(`dddd`)))
			result := map[string]interface{}{}
			json.Unmarshal(msg, &result)
			Expect(err).To(HaveOccurred())
		})

		It("it pass if appends to system CA", func() {
			msg, err := Get(regUrl, Emulated, WithSeed(1), AppendCustomCAToSystemCA, WithCAs([]byte(`dddd`)))
			result := map[string]interface{}{}
			json.Unmarshal(msg, &result)
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(expectedMatches)
		})
	})
})
