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

		It("stores a blob, undefines it, and verifies it's gone", func() {
			By("Storing the blob", func() {
				err := StoreBlob([]byte("test-data"), EmulatedTPM, WithIndex("0x1500001"))
				Expect(err).ToNot(HaveOccurred())
			})

			By("Reading the blob to confirm it exists", func() {
				data, err := ReadBlob(WithIndex("0x1500001"), EmulatedTPM)
				Expect(err).ToNot(HaveOccurred())
				Expect(data).To(Equal([]byte("test-data")))
			})

			By("Undefining the blob", func() {
				err := UndefineBlob(WithIndex("0x1500001"), EmulatedTPM)
				Expect(err).ToNot(HaveOccurred())
			})

			By("Attempting to read the undefined blob should fail", func() {
				_, err := ReadBlob(WithIndex("0x1500001"), EmulatedTPM)
				Expect(err).To(HaveOccurred())
			})

			CloseEmulatedDevice()
		})
	})
})
