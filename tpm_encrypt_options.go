package tpm

import (
	"crypto"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"
	"github.com/kairos-io/tpm-helpers/backend"
)

// TPMOptions contains configuration options for TPM operations including device path,
// key indices, attributes, passwords, and hash algorithms.
//
//nolint:revive // Allow stuttering for backwards compatibility
type TPMOptions struct {
	device   string
	index    tpmutil.Handle
	keyAttr  tpm2.TPMAObject
	nvAttr   tpm2.TPMANV
	password string
	emulated bool

	hash crypto.Hash
}

var emulatedDevice transport.TPMCloser

// CloseEmulatedDevice closes the global emulated TPM device and resets it to nil.
// This is used for cleanup when using the TPM simulator.
func CloseEmulatedDevice() {
	if emulatedDevice != nil {
		emulatedDevice.Close() //nolint:errcheck // Cleanup operation
		emulatedDevice = nil
	}
}

// TPMTransportWrapper wraps a TPM transport with information about whether it should be closed
type TPMTransportWrapper struct {
	transport.TPM
	shouldClose bool
}

// Close closes the transport only if it should be closed (not shared)
func (w *TPMTransportWrapper) Close() error {
	if w.shouldClose {
		if closer, ok := w.TPM.(transport.TPMCloser); ok {
			return closer.Close()
		}
	}
	return nil
}

func getTPMTransport(o *TPMOptions) (*TPMTransportWrapper, error) {
	if o.emulated {
		if emulatedDevice == nil {
			var err error
			emulatedDevice, err = simulator.OpenSimulator()
			if err != nil {
				return nil, err
			}
		}
		return &TPMTransportWrapper{
			TPM:         emulatedDevice,
			shouldClose: false, // Don't close shared emulated device
		}, nil
	}
	tpm, err := backend.OpenTransport(o.device)
	if err != nil {
		return nil, err
	}
	return &TPMTransportWrapper{
		TPM:         tpm,
		shouldClose: true, // Close real devices
	}, nil
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

func parseNVAttributes(s string) (tpm2.TPMANV, error) {
	var nvAttr tpm2.TPMANV
	s = strings.ReplaceAll(s, " ", "")
	for _, prop := range strings.Split(s, "|") {
		updater, ok := stringToNVAttribute[prop]
		if !ok {
			return nvAttr, fmt.Errorf("unknown attribute '%s'", prop)
		}
		updater(&nvAttr)
	}

	return nvAttr, nil
}

func parseKeyAttributes(s string) (tpm2.TPMAObject, error) {
	var keyAttr tpm2.TPMAObject
	s = strings.ReplaceAll(s, " ", "")
	for _, prop := range strings.Split(s, "|") {
		updater, ok := stringToKeyAttribute[prop]
		if !ok {
			return keyAttr, fmt.Errorf("unknown attribute property '%s'", prop)
		}
		updater(&keyAttr)
	}

	return keyAttr, nil
}
