package tpm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"

	"github.com/google/go-tpm/tpm2"
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// quotePayload mirrors the JSON GeneratePCRQuote emits.
type quotePayload struct {
	Quote struct {
		Version   string `json:"version"`
		Quote     []byte `json:"quote"`
		Signature []byte `json:"signature"`
	} `json:"quote"`
	PCRs map[int][]byte `json:"pcrs"`
}

// forgeQuote builds a syntactically valid, correctly signed TPM quote over the
// given PCRs with the given qualifying data, without needing a TPM. It is the
// software stand-in for what GeneratePCRQuote returns.
func forgeQuote(key *ecdsa.PrivateKey, nonce []byte, pcrs map[int][]byte) []byte {
	GinkgoHelper()

	selectBitmap := make([]byte, 3)
	var digestInput []byte
	for i := 0; i < 24; i++ {
		v, ok := pcrs[i]
		if !ok {
			continue
		}
		selectBitmap[i/8] |= 1 << (i % 8)
		digestInput = append(digestInput, v...)
	}
	pcrDigest := sha256.Sum256(digestInput)

	attested := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: nonce},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: selectBitmap,
				}},
			},
			PCRDigest: tpm2.TPM2BDigest{Buffer: pcrDigest[:]},
		}),
	}
	quoteBytes := tpm2.Marshal(attested)

	sum := sha256.Sum256(quoteBytes)
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	Expect(err).ToNot(HaveOccurred())

	sig := tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
		}),
	})

	var p quotePayload
	p.Quote.Version = "2"
	p.Quote.Quote = quoteBytes
	p.Quote.Signature = sig
	p.PCRs = pcrs

	out, err := json.Marshal(p)
	Expect(err).ToNot(HaveOccurred())
	return out
}

var _ = Describe("PCR quote freshness", func() {
	var key *ecdsa.PrivateKey
	var pcrs map[int][]byte
	var nonce []byte

	BeforeEach(func() {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())

		good := sha256.Sum256([]byte("known good boot"))
		pcrs = map[int][]byte{0: good[:], 7: good[:], 11: good[:]}

		nonce = make([]byte, 32)
		_, err = rand.Read(nonce)
		Expect(err).ToNot(HaveOccurred())
	})

	It("accepts a quote produced for this exchange", func() {
		verified, err := VerifyPCRQuote(forgeQuote(key, nonce, pcrs), key.Public(), nonce)
		Expect(err).ToNot(HaveOccurred())
		Expect(verified).To(Equal(pcrs))
	})

	It("rejects a quote recorded during an earlier exchange", func() {
		recorded := forgeQuote(key, []byte("nonce-from-an-old-session"), pcrs)

		_, err := VerifyPCRQuote(recorded, key.Public(), nonce)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not produced for this attestation"))
	})

	It("rejects a quote that carries no qualifying data at all", func() {
		recorded := forgeQuote(key, nil, pcrs)

		_, err := VerifyPCRQuote(recorded, key.Public(), nonce)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not produced for this attestation"))
	})

	It("refuses to verify without a nonce to check against", func() {
		_, err := VerifyPCRQuote(forgeQuote(key, nonce, pcrs), key.Public(), nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("nonce is required"))
	})
})
