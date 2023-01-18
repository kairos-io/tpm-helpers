package tpm_test

import (
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TPM Encryption", func() {
	Context("Blob", func() {
		It("encrypts a blob", func() {
			var encodedBlob []byte
			var err error
			By("Encoding the blob", func() {
				encodedBlob, err = EncodeBlob([]byte("foo"), EmulatedTPM)
				Expect(err).ToNot(HaveOccurred())
			})
			By("Decoding the blob", func() {
				foo, err := DecodeBlob(encodedBlob, EmulatedTPM)
				Expect(err).ToNot(HaveOccurred())
				Expect(foo).To(Equal([]byte("foo")))
			})
			CloseEmulatedDevice()
		})
	})
})
