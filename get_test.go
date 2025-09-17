package tpm_test

import (
	"context"
	"encoding/json"
	"fmt"
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
			if err := AuthRequest(r, conn); err != nil {
				fmt.Println("error", err.Error())
				return
			}
			awesome := r.Header.Get("awesome")
			writer, _ := conn.NextWriter(websocket.BinaryMessage)
			json.NewEncoder(writer).Encode(map[string]string{"foo": "bar", "header": awesome}) //nolint:errcheck // Test cleanup
		}
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
		for {
			if err := AuthRequest(r, conn); err != nil {
				fmt.Println("error", err.Error())
				return
			}
			defer conn.Close() //nolint:errcheck // Cleanup operation //nolint:errcheck // Cleanup operation

			v := map[string]string{}
			err := conn.ReadJSON(&v)
			if err != nil {
				fmt.Println("error", err.Error())
				return
			}
			c <- v
		}
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
		It("posts pubhash", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			rec := make(chan map[string]string, 10)
			WSServerReceiver(ctx, rec)

			conn, err := Connection("http://localhost:8080/post", Emulated, WithSeed(1))
			Expect(err).ToNot(HaveOccurred())

			defer conn.Close() //nolint:errcheck // Cleanup operation //nolint:errcheck // Cleanup operation

			err = conn.WriteJSON(map[string]string{"foo": "bar", "header": "foo"})
			Expect(err).ToNot(HaveOccurred())

			res := <-rec
			Expect(res).To(Equal(map[string]string{"foo": "bar", "header": "foo"}))
		})
	})
})

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
			json.Unmarshal(msg, &result) //nolint:errcheck // Test cleanup
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(Equal(map[string]interface{}{"foo": "bar", "header": "content"}))
		})
	})
})

// This test is meant to be running manually against a
// reg. server with a valid cert.
var _ = Describe("GET", func() {
	Context("challenges with a remote endpoint", func() {
		regURL := os.Getenv("REG_URL")

		expectedMatches := ContainElement("ros-node-{{ trunc 4 .MachineID }}")
		BeforeEach(func() {
			if regURL == "" {
				Skip("No remote url passed, skipping suite")
			}
		})

		It("gets pubhash from remote with a public signed CA", func() {
			msg, err := Get(regURL, Emulated, WithSeed(1))
			result := map[string]interface{}{}
			json.Unmarshal(msg, &result) //nolint:errcheck // Test cleanup
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(expectedMatches)
		})

		It("it fails if we specify a custom CA (invalid)", func() {
			msg, err := Get(regURL, Emulated, WithSeed(1), WithCAs([]byte(`dddd`)))
			result := map[string]interface{}{}
			json.Unmarshal(msg, &result) //nolint:errcheck // Test cleanup
			Expect(err).To(HaveOccurred())
		})

		It("it pass if appends to system CA", func() {
			msg, err := Get(regURL, Emulated, WithSeed(1), AppendCustomCAToSystemCA, WithCAs([]byte(`dddd`)))
			result := map[string]interface{}{}
			json.Unmarshal(msg, &result) //nolint:errcheck // Test cleanup
			Expect(err).ToNot(HaveOccurred())
			Expect(result).To(expectedMatches)
		})
	})
})
