package backend_test

import (
	"os"

	. "github.com/kairos-io/tpm-helpers/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SWTPM", func() {
	socket := os.Getenv("TPM_SOCKET")
	Context("opening socket connection", func() {
		It("fails on invalid files", func() {

			_, err := Socket("foobar")
			Expect(err).To(HaveOccurred())

		})

		It("dials in just fine", func() {
			if socket == "" {
				Skip("No socket file specified")
			}
			_, err := Socket(socket)
			Expect(err).ToNot(HaveOccurred())
		})
	})
})
