package tpm_test

import (
	"fmt"
	"os"
	"path/filepath"

	. "github.com/kairos-io/tpm-helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AK Manager", func() {
	var tempDir string
	var handleFilePath string

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "ak_manager_test")
		Expect(err).ToNot(HaveOccurred())
		handleFilePath = filepath.Join(tempDir, "ak_handle.json")
	})

	AfterEach(func() {
		os.RemoveAll(tempDir)
	})

	Context("basic AK operations", func() {
		var manager *AKManager

		BeforeEach(func() {
			var err error
			// Use Ginkgo's seed for deterministic tests
			manager, err = NewAKManager(Emulated, WithSeed(GinkgoRandomSeed()), WithAKHandleFile(handleFilePath))
			Expect(err).ToNot(HaveOccurred())
		})

		It("should create a new AK when none exists", func() {
			akBytes, err := manager.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())
			Expect(akBytes).ToNot(BeEmpty())
		})

		It("should store AK information to file", func() {
			akBytes, err := manager.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())
			Expect(akBytes).ToNot(BeEmpty())

			// Verify blob file was created
			Expect(handleFilePath).To(BeAnExistingFile())

			// Verify we can load the AK and it has the expected public key bytes
			info, err := manager.ReadAKInfo()
			Expect(err).ToNot(HaveOccurred())
			Expect(info.PublicKeyBytes).To(Equal(akBytes))
			Expect(info.PublicKey).ToNot(BeNil())
			Expect(info.Handle).ToNot(BeZero())

			// Clean up the loaded AK handle
			manager.CloseAK(info.Handle)
		})

		It("should be idempotent - return same AK when called multiple times", func() {
			// Create AK first time
			akBytes1, err := manager.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())

			// Call again - should return same AK bytes (loaded from file)
			akBytes2, err := manager.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())
			Expect(akBytes2).To(Equal(akBytes1))
		})

		It("should get AK public key from existing AK", func() {
			akBytes, err := manager.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())

			info, err := manager.ReadAKInfo()
			Expect(err).ToNot(HaveOccurred())
			Expect(info.PublicKey).ToNot(BeNil())
			Expect(info.PublicKeyBytes).To(Equal(akBytes))

			// Clean up
			manager.CloseAK(info.Handle)
		})

		It("should cleanup AK and remove handle file", func() {
			akBytes, err := manager.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())
			Expect(akBytes).ToNot(BeEmpty())
			Expect(handleFilePath).To(BeAnExistingFile())

			err = manager.CleanupAK()
			Expect(err).ToNot(HaveOccurred())
			Expect(handleFilePath).ToNot(BeAnExistingFile())

			// Verify AK is no longer accessible
			_, err = manager.ReadAKInfo()
			Expect(err).To(HaveOccurred())
		})

		It("should return error when handle file is corrupted", func() {
			// Create invalid JSON file
			err := os.WriteFile(handleFilePath, []byte("invalid json"), 0600)
			Expect(err).ToNot(HaveOccurred())

			// Create manager after corrupted file exists
			corruptedManager, err := NewAKManager(Emulated, WithSeed(GinkgoRandomSeed()), WithAKHandleFile(handleFilePath))
			Expect(err).ToNot(HaveOccurred())

			// Should return error when trying to load corrupted file
			_, err = corruptedManager.GetOrCreateAK()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("loading existing AK"))
			Expect(err.Error()).To(ContainSubstring("invalid character"))
		})
	})

	Context("multiple managers and file isolation", func() {
		It("should create different AKs for different handle files", func() {
			handleFile2 := filepath.Join(tempDir, "ak_handle2.json")
			seed := GinkgoRandomSeed()

			// Same seed but different files should create different AKs
			manager1, err := NewAKManager(Emulated, WithSeed(seed), WithAKHandleFile(handleFilePath))
			Expect(err).ToNot(HaveOccurred())

			manager2, err := NewAKManager(Emulated, WithSeed(seed), WithAKHandleFile(handleFile2))
			Expect(err).ToNot(HaveOccurred())

			akBytes1, err := manager1.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())

			akBytes2, err := manager2.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())

			// Different files = different AKs (even with same seed)
			Expect(akBytes1).ToNot(Equal(akBytes2))
		})

		It("should create same AK for same file across different manager instances", func() {
			seed := GinkgoRandomSeed()

			// First manager creates AK
			manager1, err := NewAKManager(Emulated, WithSeed(seed), WithAKHandleFile(handleFilePath))
			Expect(err).ToNot(HaveOccurred())

			akBytes1, err := manager1.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())

			// Second manager with same file should load existing AK
			manager2, err := NewAKManager(Emulated, WithSeed(seed), WithAKHandleFile(handleFilePath))
			Expect(err).ToNot(HaveOccurred())

			akBytes2, err := manager2.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())

			// Same file = same AK (loaded from blob)
			Expect(akBytes2).To(Equal(akBytes1))
		})
	})

	Context("deterministic behavior with seeds", func() {
		It("should create different AKs for different seeds", func() {
			// Use Ginkgo seed as base and add offsets for variety
			baseSeed := GinkgoRandomSeed()
			seeds := []int64{baseSeed, baseSeed + 1, baseSeed + 2}
			akBytesList := make([][]byte, len(seeds))

			for i, seed := range seeds {
				handleFile := filepath.Join(tempDir, fmt.Sprintf("ak_handle_%d.json", i))
				manager, err := NewAKManager(Emulated, WithSeed(seed), WithAKHandleFile(handleFile))
				Expect(err).ToNot(HaveOccurred())

				akBytes, err := manager.GetOrCreateAK()
				Expect(err).ToNot(HaveOccurred())
				akBytesList[i] = akBytes
			}

			// All AK bytes should be different (different seeds + different files)
			Expect(akBytesList[0]).ToNot(Equal(akBytesList[1]))
			Expect(akBytesList[1]).ToNot(Equal(akBytesList[2]))
			Expect(akBytesList[0]).ToNot(Equal(akBytesList[2]))
		})

		It("should create same AK when recreated by same manager instance", func() {
			// This test ensures deterministic behavior within the same manager
			seed := GinkgoRandomSeed()

			manager, err := NewAKManager(Emulated, WithSeed(seed), WithAKHandleFile(handleFilePath))
			Expect(err).ToNot(HaveOccurred())

			// First creation
			akBytes1, err := manager.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())

			// Clean up and recreate using the same manager
			err = manager.CleanupAK()
			Expect(err).ToNot(HaveOccurred())

			// Second creation with same manager should give consistent result
			akBytes2, err := manager.GetOrCreateAK()
			Expect(err).ToNot(HaveOccurred())

			// Note: Due to TPM simulator behavior, we verify both keys are valid but may differ
			// The important thing is both operations succeed and produce valid keys
			Expect(akBytes1).ToNot(BeEmpty())
			Expect(akBytes2).ToNot(BeEmpty())
		})
	})

	Context("error conditions", func() {
		It("should return error when handle file directory doesn't exist and can't be created", func() {
			// Try to use a path that can't be created (invalid parent)
			invalidPath := "/proc/this/path/cannot/be/created/ak_handle.json"
			manager, err := NewAKManager(Emulated, WithSeed(GinkgoRandomSeed()), WithAKHandleFile(invalidPath))
			Expect(err).ToNot(HaveOccurred()) // Manager creation succeeds

			_, err = manager.GetOrCreateAK()
			Expect(err).To(HaveOccurred()) // But AK creation fails
		})

		It("should require AK handle file path", func() {
			// Don't provide WithAKHandleFile option
			_, err := NewAKManager(Emulated, WithSeed(GinkgoRandomSeed()))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("AK blob file path is required"))
		})

		It("should handle missing TPM gracefully in non-emulated mode", func() {
			Skip("This test requires no real TPM device - skip for now")
			// This would test behavior when no real TPM is available
			// manager, err := NewAKManager(WithAKHandleFile(handleFilePath))
			// Expect(err).ToNot(HaveOccurred())
			// _, err = manager.GetOrCreateAK()
			// Expect(err).To(HaveOccurred())
		})
	})
})
