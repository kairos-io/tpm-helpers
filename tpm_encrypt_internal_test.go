package tpm

import (
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// eccHandle is a persistent handle that no other spec uses. 0x81000001 would be
// the realistic one, it is where the TCG provisioning guidance puts the ECC
// storage root key, but a spec that squats on it would be confusing to read.
const eccHandle = 0x81000009

// persistECCKeyAt creates an ECC primary and evicts it to handle, so the handle
// holds a key that EncryptBlob cannot use.
func persistECCKeyAt(tpm transport.TPM, handle tpm2.TPMHandle) {
	GinkgoHelper()

	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	Expect(err).ToNot(HaveOccurred())

	_, err = tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name},
		PersistentHandle: handle,
	}.Execute(tpm)
	Expect(err).ToNot(HaveOccurred())
}

var _ = Describe("TPM Encryption, a handle that is not ours", func() {
	var tpm *TPMTransportWrapper

	BeforeEach(func() {
		o, err := DefaultTPMOption(EmulatedTPM)
		Expect(err).ToNot(HaveOccurred())

		tpm, err = getTPMTransport(o)
		Expect(err).ToNot(HaveOccurred())

		persistECCKeyAt(tpm, eccHandle)
		DeferCleanup(CloseEmulatedDevice)
	})

	It("reports the handle instead of panicking", func() {
		_, err := EncryptBlob([]byte("foo"), EmulatedTPM, WithIndex("0x81000009"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("0x81000009"))
		Expect(err.Error()).To(ContainSubstring("key is not RSA"))
	})

	It("does not hand out a nil *rsa.PublicKey", func() {
		k := &TPMRSAPrivateKey{transport: tpm, handle: eccHandle}

		// A nil k.publicKey returned as a crypto.PublicKey satisfies this
		// assertion and panics at the first use, which is what EncryptBlob did.
		_, ok := k.Public().(*rsa.PublicKey)
		Expect(ok).To(BeFalse())
	})

	It("still encrypts against a handle it owns", func() {
		blob, err := EncryptBlob([]byte("foo"), EmulatedTPM, WithIndex("0x8100000a"))
		Expect(err).ToNot(HaveOccurred())

		got, err := DecryptBlob(blob, EmulatedTPM, WithIndex("0x8100000a"))
		Expect(err).ToNot(HaveOccurred())
		Expect(got).To(Equal([]byte("foo")))
	})
})
