package tpm_test

import (
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TPM Encryption", func() {
	Context("Blob", func() {
		It("encrypts a blob", func() {
			var encryptedBlob []byte
			var err error
			By("Encrypting the blob", func() {
				encryptedBlob, err = EncryptBlob([]byte("foo"), EmulatedTPM)
				Expect(err).ToNot(HaveOccurred())
			})
			By("Decrypting the blob", func() {
				foo, err := DecryptBlob(encryptedBlob, EmulatedTPM)
				Expect(err).ToNot(HaveOccurred())
				Expect(foo).To(Equal([]byte("foo")))
			})
			CloseEmulatedDevice()
		})
	})
})
