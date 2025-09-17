package tpm

import (
	"crypto"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TPMOptions contains configuration options for TPM operations including device path,
// key indices, attributes, passwords, and hash algorithms.
//
//nolint:revive // Allow stuttering for backwards compatibility
type TPMOptions struct {
	device   string
	index    tpmutil.Handle
	keyAttr  tpm2.KeyProp
	nvAttr   tpm2.NVAttr
	password string
	emulated bool

	hash crypto.Hash
}

var emulatedDevice io.ReadWriteCloser

// CloseEmulatedDevice closes the global emulated TPM device and resets it to nil.
// This is used for cleanup when using the TPM simulator.
func CloseEmulatedDevice() {
	emulatedDevice.Close() //nolint:errcheck // Cleanup operation
	emulatedDevice = nil
}

func getTPMDevice(o *TPMOptions) (io.ReadWriteCloser, error) {
	if o.emulated {
		if emulatedDevice == nil {
			var err error
			emulatedDevice, err = simulator.Get()
			if err != nil {
				return nil, err
			}
		}
		return emulatedDevice, nil
	}
	dev, err := tpmk.OpenDevice(o.device)
	if err != nil {
		return dev, err
	}
	return dev, err
}

// DefaultTPMOption creates a new TPMOptions struct with sensible defaults
// and applies any provided options on top of the defaults.
func DefaultTPMOption(opts ...TPMOption) (*TPMOptions, error) {
	o := &TPMOptions{}

	defaults := []TPMOption{
		WithAttributes("sign|decrypt|userwithauth|sensitivedataorigin"),
		WithNVAttributes("ownerwrite|ownerread|authread|ppread"),
		WithIndex("0x81000008"),
		WithDevice("/dev/tpmrm0"),
		WithHash(crypto.SHA256),
	}

	return o, o.Apply(append(defaults, opts...)...)
}

// TPMOption is a functional option type for configuring TPMOptions.
//
//nolint:revive // Allow stuttering for backwards compatibility
type TPMOption func(t *TPMOptions) error

// Apply applies a list of TPMOption functions to the TPMOptions struct,
// returning an error if any option fails to apply.
func (t *TPMOptions) Apply(opts ...TPMOption) error {
	for _, o := range opts {
		if err := o(t); err != nil {
			return err
		}
	}

	return nil
}

// EmulatedTPM is a TPMOption that configures the TPM to use an emulated device
// instead of a physical TPM hardware device.
var EmulatedTPM TPMOption = func(t *TPMOptions) error {
	t.emulated = true
	return nil
}

// WithHash returns a TPMOption that sets the hash algorithm to use for cryptographic operations.
func WithHash(c crypto.Hash) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.hash = c
		return
	}
}

// WithPassword returns a TPMOption that sets the password for TPM key operations.
func WithPassword(s string) TPMOption {
	return func(t *TPMOptions) error {
		t.password = s
		return nil
	}
}

// WithDevice returns a TPMOption that sets the TPM device path (e.g., "/dev/tpmrm0").
func WithDevice(s string) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.device = s
		return
	}
}

// WithAttributes returns a TPMOption that sets the key attributes from a pipe-separated string
// (e.g., "sign|decrypt|userwithauth|sensitivedataorigin").
func WithAttributes(s string) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.keyAttr, err = parseKeyAttributes(s)
		return
	}
}

// WithIndex returns a TPMOption that sets the TPM handle index from a string
// (e.g., "0x81000008" for a persistent key handle).
func WithIndex(s string) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.index, err = parseHandle(s)
		return
	}
}

// WithNVAttributes returns a TPMOption that sets the NV (Non-Volatile) storage attributes
// from a pipe-separated string (e.g., "ownerwrite|ownerread|authread|ppread").
func WithNVAttributes(s string) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.nvAttr, err = parseNVAttributes(s)
		return
	}
}

func parseHandle(s string) (tpmutil.Handle, error) {
	i, err := strconv.ParseUint(s, 0, 32)
	return tpmutil.Handle(i), err
}

func parseNVAttributes(s string) (tpm2.NVAttr, error) {
	var nvAttr tpm2.NVAttr
	s = strings.Replace(s, " ", "", -1)
	for _, prop := range strings.Split(s, "|") {
		v, ok := stringToNVAttribute[prop]
		if !ok {
			return nvAttr, fmt.Errorf("unknown attribute '%s'", prop)
		}
		nvAttr |= v
	}

	return nvAttr, nil
}

func parseKeyAttributes(s string) (tpm2.KeyProp, error) {
	var keyProp tpm2.KeyProp
	s = strings.Replace(s, " ", "", -1)
	for _, prop := range strings.Split(s, "|") {
		v, ok := stringToKeyAttribute[prop]
		if !ok {
			return keyProp, fmt.Errorf("unknown attribute property '%s'", prop)
		}
		keyProp |= v
	}

	return keyProp, nil
}
