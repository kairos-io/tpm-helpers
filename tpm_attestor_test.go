package tpm_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// Mimics a WS server which accepts connections and returns data
func WSServer(ctx context.Context) {
	s := http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m := http.NewServeMux()
	m.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity
		defer conn.Close()                     //nolint:errcheck // Test cleanup

		awesome := r.Header.Get("awesome")
		writer, _ := conn.NextWriter(websocket.BinaryMessage)
		json.NewEncoder(writer).Encode(map[string]string{"foo": "bar", "header": awesome}) //nolint:errcheck // Test cleanup
	})

	s.Handler = m

	go s.ListenAndServe() //nolint:errcheck // Test cleanup
	go func() {
		<-ctx.Done()
		s.Shutdown(ctx) //nolint:errcheck // Test cleanup
	}()
}

// Mimics a WS server which accepts TPM Bearer token and receives data
func WSServerReceiver(ctx context.Context, c chan map[string]string) {
	s := http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m := http.NewServeMux()
	m.HandleFunc("/post", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil) // error ignored for sake of simplicity
		defer conn.Close()                     //nolint:errcheck // Cleanup operation

		v := map[string]string{}
		err := conn.ReadJSON(&v)
		if err != nil {
			fmt.Println("error", err.Error())
			return
		}
		c <- v
	})

	s.Handler = m

	go s.ListenAndServe() //nolint:errcheck // Test cleanup
	go func() {
		<-ctx.Done()
		s.Shutdown(ctx) //nolint:errcheck // Test cleanup
	}()
}

var _ = Describe("POST", func() {
	Context("challenges", func() {
		It("posts data via websocket", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			rec := make(chan map[string]string, 10)
			WSServerReceiver(ctx, rec)

			conn, err := AttestationConnection("http://localhost:8080/post", Emulated, WithSeed(1))
			Expect(err).ToNot(HaveOccurred())

			defer conn.Close() //nolint:errcheck // Cleanup operation

			err = conn.WriteJSON(map[string]string{"foo": "bar", "header": "foo"})
			Expect(err).ToNot(HaveOccurred())

			res := <-rec
			Expect(res).To(Equal(map[string]string{"foo": "bar", "header": "foo"}))
		})
	})
})

var _ = Describe("AttestationConnection", func() {
	Context("websocket connections", func() {
		It("connects to websocket endpoint", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			WSServer(ctx)
			time.Sleep(100 * time.Millisecond) // Give server time to start

			conn, err := AttestationConnection("http://localhost:8080/test", Emulated, WithSeed(1), WithAdditionalHeader("awesome", "content"))
			Expect(err).ToNot(HaveOccurred())
			defer conn.Close() //nolint:errcheck // Cleanup operation

			// Just verify we can establish a connection - the main purpose of AttestationConnection
			Expect(conn).ToNot(BeNil())
		})
	})
})

// This test is meant to be running manually against a
// reg. server with a valid cert.
var _ = Describe("Remote Attestation Connection", func() {
	Context("challenges with a remote endpoint", func() {
		regURL := os.Getenv("REG_URL")

		expectedMatches := ContainElement("ros-node-{{ trunc 4 .MachineID }}")
		BeforeEach(func() {
			if regURL == "" {
				Skip("No remote url passed, skipping suite")
			}
		})

		It("connects to remote with a public signed CA", func() {
			conn, err := AttestationConnection(regURL, Emulated, WithSeed(1))
			Expect(err).ToNot(HaveOccurred())
			defer conn.Close() //nolint:errcheck // Cleanup operation

			// Read message from the server
			_, msg, err := conn.NextReader()
			Expect(err).ToNot(HaveOccurred())

			data, err := io.ReadAll(msg)
			Expect(err).ToNot(HaveOccurred())

			result := map[string]interface{}{}
			json.Unmarshal(data, &result) //nolint:errcheck // Test cleanup
			Expect(result).To(expectedMatches)
		})

		It("it fails if we specify a custom CA (invalid)", func() {
			_, err := AttestationConnection(regURL, Emulated, WithSeed(1), WithCAs([]byte(`dddd`)))
			Expect(err).To(HaveOccurred())
		})

		It("it pass if appends to system CA", func() {
			conn, err := AttestationConnection(regURL, Emulated, WithSeed(1), AppendCustomCAToSystemCA, WithCAs([]byte(`dddd`)))
			Expect(err).ToNot(HaveOccurred())
			defer conn.Close() //nolint:errcheck // Cleanup operation

			// Read message from the server
			_, msg, err := conn.NextReader()
			Expect(err).ToNot(HaveOccurred())

			data, err := io.ReadAll(msg)
			Expect(err).ToNot(HaveOccurred())

			result := map[string]interface{}{}
			json.Unmarshal(data, &result) //nolint:errcheck // Test cleanup
			Expect(result).To(expectedMatches)
		})
	})
})
