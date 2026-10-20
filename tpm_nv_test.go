package tpm_test

import (
	"math"

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

	Context("an index that already exists", func() {
		It("replaces a blob with a shorter one, instead of splicing them", func() {
			// An NV index keeps the size it was defined with, so without a
			// resize the shorter write leaves the tail of the first blob in
			// place and ReadBlob returns "shorthrase-number-one".
			idx := "0x1500010"
			Expect(StoreBlob([]byte("passphrase-number-one"), EmulatedTPM, WithIndex(idx))).To(Succeed())
			Expect(StoreBlob([]byte("short"), EmulatedTPM, WithIndex(idx))).To(Succeed())

			got, err := ReadBlob(WithIndex(idx), EmulatedTPM)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(Equal([]byte("short")))

			CloseEmulatedDevice()
		})

		It("replaces a blob with a longer one, instead of failing on the old size", func() {
			// Without a resize the write runs past the end of the index and
			// the TPM answers TPM_RC_NV_RANGE, leaving the old blob in place.
			idx := "0x1500011"
			Expect(StoreBlob([]byte("short"), EmulatedTPM, WithIndex(idx))).To(Succeed())
			Expect(StoreBlob([]byte("a-much-longer-passphrase"), EmulatedTPM, WithIndex(idx))).To(Succeed())

			got, err := ReadBlob(WithIndex(idx), EmulatedTPM)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(Equal([]byte("a-much-longer-passphrase")))

			CloseEmulatedDevice()
		})

		It("keeps an index of the same size, so a same-size store does not destroy it", func() {
			idx := "0x1500012"
			Expect(StoreBlob([]byte("aaaa"), EmulatedTPM, WithIndex(idx))).To(Succeed())
			Expect(StoreBlob([]byte("bbbb"), EmulatedTPM, WithIndex(idx))).To(Succeed())

			got, err := ReadBlob(WithIndex(idx), EmulatedTPM)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(Equal([]byte("bbbb")))

			CloseEmulatedDevice()
		})

		It("refuses a blob that does not fit an NV index's size field", func() {
			err := StoreBlob(make([]byte, math.MaxUint16+1), EmulatedTPM, WithIndex("0x1500013"))
			Expect(err).To(MatchError(ContainSubstring("does not fit an NV index")))

			CloseEmulatedDevice()
		})
	})
})
