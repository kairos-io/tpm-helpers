package tpm_test

import (
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("TPM NV", func() {
	Context("NV store", func() {
		It("stores a blob and get it back", func() {
			By("Storing the blob", func() {
				// authwrite matters here!
				err := StoreBlob([]byte("foo"), EmulatedTPM, WithIndex("0x1500000"))
				Expect(err).ToNot(HaveOccurred())
			})
			By("Reading the blob", func() {
				foo, err := ReadBlob(WithIndex("0x1500000"), EmulatedTPM)
				Expect(err).ToNot(HaveOccurred())
				Expect(foo).To(Equal([]byte("foo")))
			})
			CloseEmulatedDevice()
		})
	})
})
