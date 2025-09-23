package tpm_test

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const TestHeader = "awesome"

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

		headerValue := r.Header.Get(TestHeader)
		writer, _ := conn.NextWriter(websocket.BinaryMessage)
		json.NewEncoder(writer).Encode(map[string]string{"foo": "bar", "header": headerValue}) //nolint:errcheck // Test cleanup
		writer.Close()                                                                         //nolint:errcheck // Test cleanup - properly close the writer
	})

	s.Handler = m

	go s.ListenAndServe() //nolint:errcheck // Test cleanup
	go func() {
		<-ctx.Done()
		s.Shutdown(ctx) //nolint:errcheck // Test cleanup
	}()
}

var _ = Describe("AttestationConnection Basic Functionality", func() {
	Context("connection establishment", func() {
		It("establishes WebSocket connection without performing authentication", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Start a simple WebSocket server that accepts connections
			WSServer(ctx)
			time.Sleep(100 * time.Millisecond) // Give server time to start

			conn, err := AttestationConnection("http://localhost:8080/test", Emulated, WithSeed(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(conn).ToNot(BeNil())

			defer conn.Close() //nolint:errcheck // Cleanup operation

			// Verify this is just connection establishment - no authentication has occurred yet
			// The connection should be ready for the subsequent attestation protocol steps
		})

		It("sends custom headers during WebSocket handshake", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			WSServer(ctx)
			time.Sleep(100 * time.Millisecond) // Give server time to start

			conn, err := AttestationConnection("http://localhost:8080/test", Emulated, WithSeed(1), WithAdditionalHeader(TestHeader, "test-header-value"))
			Expect(err).ToNot(HaveOccurred())
			Expect(conn).ToNot(BeNil())

			defer conn.Close() //nolint:errcheck // Cleanup operation

			// Read the response from the server which should include our header value
			// The server immediately sends a response with the header value and closes
			result := map[string]interface{}{}
			err = conn.ReadJSON(&result)
			Expect(err).ToNot(HaveOccurred())

			// The WSServer echoes back the "awesome" header value in the response
			Expect(result["header"]).To(Equal("test-header-value"))
		})

		It("handles connection errors gracefully", func() {
			// Try to connect to a non-existent server
			_, err := AttestationConnection("http://localhost:9999/nonexistent", Emulated, WithSeed(1))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connection refused"))
		})

		It("supports different TPM configurations", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			WSServer(ctx)
			time.Sleep(100 * time.Millisecond) // Give server time to start

			// Test with different seeds to ensure different TPM configurations work
			conn1, err := AttestationConnection("http://localhost:8080/test", Emulated, WithSeed(1))
			Expect(err).ToNot(HaveOccurred())
			Expect(conn1).ToNot(BeNil())
			defer conn1.Close() //nolint:errcheck // Cleanup operation

			conn2, err := AttestationConnection("http://localhost:8080/test", Emulated, WithSeed(42))
			Expect(err).ToNot(HaveOccurred())
			Expect(conn2).ToNot(BeNil())
			defer conn2.Close() //nolint:errcheck // Cleanup operation
		})
	})
})
