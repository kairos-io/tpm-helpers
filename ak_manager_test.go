package tpm_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/google/go-attestation/attest"
	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AK Manager - Transient AK Implementation", func() {
	Context("basic transient AK operations", func() {
		var manager *AKManager

		BeforeEach(func() {
			var err error
			// Use Ginkgo's seed for deterministic tests
			manager, err = NewAKManager(Emulated, WithSeed(GinkgoRandomSeed()))
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			if manager != nil {
				manager.Close() //nolint:errcheck
			}
		})

		It("should expose AK attestation parameters", func() {
			params, err := manager.AKParams()
			Expect(err).ToNot(HaveOccurred())
			Expect(params).ToNot(BeNil())
			Expect(params.Public).ToNot(BeEmpty())
		})

		It("should get EK from TPM", func() {
			ek, err := manager.GetEK()
			Expect(err).ToNot(HaveOccurred())
			Expect(ek).ToNot(BeNil())
			Expect(ek.Public).ToNot(BeNil())
		})

		It("should get AK public key bytes", func() {
			publicKeyBytes, err := manager.GetAKPublicKeyBytes()
			Expect(err).ToNot(HaveOccurred())
			Expect(publicKeyBytes).ToNot(BeEmpty())
		})

		It("should get attestation data for challenge generation", func() {
			ek, attestationParams, err := manager.GetAttestationData()
			Expect(err).ToNot(HaveOccurred())
			Expect(ek).ToNot(BeNil())
			Expect(attestationParams).ToNot(BeNil())
			Expect(attestationParams.Public).ToNot(BeEmpty())
		})

		It("should get AK public key as crypto.PublicKey", func() {
			pubKey, err := manager.GetAKPublicKey()
			Expect(err).ToNot(HaveOccurred())
			Expect(pubKey).ToNot(BeNil())

			// Verify we get a valid crypto.PublicKey (RSA or ECDSA)
			switch key := pubKey.(type) {
			case *rsa.PublicKey:
				// Validate RSA public key components
				Expect(key.N).ToNot(BeNil(), "RSA modulus should not be nil")
				Expect(key.N.Sign()).To(Equal(1), "RSA modulus should be positive")
				Expect(key.N.BitLen()).To(BeNumerically(">=", 1024), "RSA key should be at least 1024 bits")
				Expect(key.E).To(BeNumerically(">", 1), "RSA exponent should be > 1")
				Expect(key.E).To(BeNumerically("<=", 1<<31-1), "RSA exponent should be reasonable")

			case *ecdsa.PublicKey:
				// Validate the ECDSA public key without touching the raw big.Int
				// coordinates (key.X/key.Y and Curve.IsOnCurve are deprecated as of
				// Go 1.26). (*ecdsa.PublicKey).ECDH() returns an error when the key is
				// not on the curve or is the point at infinity, so it covers the same
				// checks.
				Expect(key.Curve).ToNot(BeNil(), "ECDSA curve should not be nil")

				ecdhKey, err := key.ECDH()
				Expect(err).ToNot(HaveOccurred(), "ECDSA public key should be valid (on-curve and not the point at infinity)")
				Expect(ecdhKey.Bytes()).ToNot(BeEmpty(), "ECDSA public key encoding should not be empty")

			default:
				Fail(fmt.Sprintf("Expected RSA or ECDSA public key, got %T", pubKey))
			}
		})
	})

	// uniqueness tests removed; manager caches a single AK per instance

	Context("PCR quote generation", func() {
		var manager *AKManager

		BeforeEach(func() {
			var err error
			manager, err = NewAKManager(Emulated, WithSeed(GinkgoRandomSeed()))
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			if manager != nil {
				manager.Close() //nolint:errcheck
			}
		})

		It("should generate PCR quote with specified PCRs", func() {
			pcrs := []int{0, 7, 11}
			quoteBytes, err := manager.GeneratePCRQuote(pcrs)
			Expect(err).ToNot(HaveOccurred())
			Expect(quoteBytes).ToNot(BeEmpty())

			// Verify quote is valid JSON structure
			var payload map[string]interface{}
			err = json.Unmarshal(quoteBytes, &payload)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should return error for invalid PCR indices", func() {
			invalidPCRs := []int{-1, 24, 100}
			_, err := manager.GeneratePCRQuote(invalidPCRs)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("out of range"))
		})

		It("should return error for empty PCR list", func() {
			emptyPCRs := []int{}
			_, err := manager.GeneratePCRQuote(emptyPCRs)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("at least one PCR"))
		})
	})

	Context("complete attestation workflow", func() {
		var manager *AKManager

		BeforeEach(func() {
			var err error
			manager, err = NewAKManager(Emulated, WithSeed(GinkgoRandomSeed()))
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			if manager != nil {
				manager.Close() //nolint:errcheck
			}
		})

		It("should complete full attestation workflow with PCR quote", func() {
			// Get attestation data to create a valid challenge
			ek, akParams, err := manager.GetAttestationData()
			Expect(err).ToNot(HaveOccurred())

			// Generate a challenge using the existing GenerateChallenge function
			ap := attest.ActivationParameters{TPMVersion: attest.TPMVersion20, EK: ek.Public, AK: *akParams}
			expectedSecret, ec, err := ap.Generate()
			Expect(err).ToNot(HaveOccurred())
			Expect(expectedSecret).ToNot(BeEmpty())
			challenge := ec

			// Parse the challenge
			// Test ActivateCredential directly
			secret, err := manager.ActivateCredential(challenge)
			Expect(err).ToNot(HaveOccurred())
			Expect(secret).To(Equal(expectedSecret))

			// Test CreateProofRequest with complete PCR quote
			challengeResp := &AttestationChallengeResponse{Challenge: challenge}
			proofReq, err := manager.CreateProofRequest(challengeResp, []int{0, 7, 11})
			Expect(err).ToNot(HaveOccurred())
			Expect(proofReq).ToNot(BeNil())
			Expect(proofReq.Secret).To(Equal(expectedSecret))
			Expect(proofReq.PCRQuote).ToNot(BeEmpty())

			// Verify PCR quote is valid JSON with proper structure
			var quoteData map[string]interface{}
			err = json.Unmarshal(proofReq.PCRQuote, &quoteData)
			Expect(err).ToNot(HaveOccurred())
			Expect(quoteData["quote"]).ToNot(BeNil())
			Expect(quoteData["pcrs"]).ToNot(BeNil())

			// Verify default PCRs are selected (0, 7, 11) by checking PCR map keys
			pcrsMap := quoteData["pcrs"].(map[string]interface{})
			expectedPCRs := []string{"0", "7", "11"}
			for _, expectedPCR := range expectedPCRs {
				Expect(pcrsMap).To(HaveKey(expectedPCR))
			}

			// Verify quote structure has expected fields
			quoteInfo := quoteData["quote"].(map[string]interface{})
			Expect(quoteInfo["version"]).ToNot(BeNil())
			Expect(quoteInfo["quote"]).ToNot(BeNil())
			Expect(quoteInfo["signature"]).ToNot(BeNil())
		})

		// certification validation test removed (implicit via credential activation)

		It("should return error when activating invalid credentials", func() {
			// Test with empty/invalid challenge - this will fail at the TPM level
			emptyChallenge := &attest.EncryptedCredential{}
			_, err := manager.ActivateCredential(emptyChallenge)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("activating credential"))
		})

		It("should return error when creating proof request with invalid challenge", func() {
			// Test with empty challenge response - this will fail at credential activation
			emptyResp := &AttestationChallengeResponse{Challenge: &attest.EncryptedCredential{}}
			_, err := manager.CreateProofRequest(emptyResp, []int{0})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("activating credential"))
		})
	})

	Context("manager lifecycle", func() {
		It("should properly close TPM session", func() {
			manager, err := NewAKManager(Emulated, WithSeed(GinkgoRandomSeed()))
			Expect(err).ToNot(HaveOccurred())

			// Ensure manager exposes AK params (session active)
			_, err = manager.AKParams()
			Expect(err).ToNot(HaveOccurred())

			// Close manager should succeed
			err = manager.Close()
			Expect(err).ToNot(HaveOccurred())

			// Subsequent close should not error
			err = manager.Close()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should handle multiple managers independently", func() {
			seed := GinkgoRandomSeed()

			By("creating manager1")
			manager1, err := NewAKManager(Emulated, WithSeed(seed))
			Expect(err).ToNot(HaveOccurred())
			ek1, err := manager1.GetEK()
			Expect(err).ToNot(HaveOccurred())
			manager1.Close() //nolint:errcheck

			By("creating manager2")
			manager2, err := NewAKManager(Emulated, WithSeed(seed))
			Expect(err).ToNot(HaveOccurred())
			ek2, err := manager2.GetEK()
			Expect(err).ToNot(HaveOccurred())
			manager2.Close() //nolint:errcheck

			// EKs should be the same (same TPM simulator with same seed)
			Expect(ek1.Public).To(Equal(ek2.Public))
		})
	})
})
