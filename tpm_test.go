package tpm_test

import (
	"os"

	. "github.com/kairos-io/tpm-helpers"
	. "github.com/kairos-io/tpm-helpers/backend"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Simulated TPM", func() {
	Context("opening socket connection", func() {
		It("dials in just fine", func() {
			str, err := GetPubHash(Emulated)
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeEmpty())
		})
	})

	Context("specifying a seed", func() {
		It("same pubkey with same seed", func() {
			str, err := GetPubHash(Emulated, WithSeed(1))
			Expect(err).ToNot(HaveOccurred())
			str2, err := GetPubHash(Emulated, WithSeed(1))
			Expect(err).ToNot(HaveOccurred())
			str3, err := GetPubHash(Emulated, WithSeed(2))
			Expect(err).ToNot(HaveOccurred())
			Expect(str).To(Equal(str2))
			Expect(str).ToNot(Equal(str3))
		})
	})

	Context("from a socket", func() {
		// In order to run this test a swtpm socket is required. e.g.:
		// swtpm socket --server type=unixio,path=/tmp/tpm-server --ctrl type=unixio,path=/tmp/tpm-ctrl --tpm2
		// TPM_SOCKET=/tmp/tpm-ctrl ginkgo -r ./

		socket := os.Getenv("TPM_SOCKET")
		It("gets pubhash", func() {
			if socket == "" {
				Skip("No socket file specified")
			}

			b, err := Socket(socket)
			Expect(err).ToNot(HaveOccurred())

			str, err := GetPubHash(WithCommandChannel(b))
			Expect(err).ToNot(HaveOccurred())
			Expect(str).ToNot(BeEmpty())
		})
	})
})
