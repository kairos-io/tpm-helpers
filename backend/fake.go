package backend

import (
	"io"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2/transport"
)

// FakeTPM is a wrapper for fake TPM devices
type FakeTPM struct {
	io.ReadWriteCloser
}

var fixedLog = []byte{0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x21, 0x0, 0x0, 0x0, 0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44,
	0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x2, 0x0, 0x2, 0x1, 0x0, 0x0, 0x0, 0xb, 0x0, 0x20, 0x0, 0x0}

// MeasurementLog returns static log data to comply to TPM interface
func (*FakeTPM) MeasurementLog() ([]byte, error) { return fixedLog, nil }

// Fake returns a fake TPM-satisfying interface from a ReadWriteCloser
func Fake(rw io.ReadWriteCloser) *FakeTPM {
	return &FakeTPM{ReadWriteCloser: rw}
}

// transportCommandChannel wraps a transport.TPM to implement attest.CommandChannelTPM20
// It adapts the transport.TPM Send interface to ReadWriteCloser
type transportCommandChannel struct {
	tpm transport.TPM
	// Buffer for pending reads
	readBuf []byte
	readPos int
}

// Read reads data from the TPM response buffer
func (t *transportCommandChannel) Read(p []byte) (int, error) {
	if t.readPos >= len(t.readBuf) {
		return 0, io.EOF
	}
	n := copy(p, t.readBuf[t.readPos:])
	t.readPos += n
	return n, nil
}

// Write sends a command to the TPM and buffers the response
func (t *transportCommandChannel) Write(p []byte) (int, error) {
	response, err := t.tpm.Send(p)
	if err != nil {
		return 0, err
	}
	// Buffer the response for Read
	t.readBuf = response
	t.readPos = 0
	return len(p), nil
}

// Send sends a command to the TPM and returns the response
func (t *transportCommandChannel) Send(command []byte) ([]byte, error) {
	return t.tpm.Send(command)
}

// MeasurementLog returns empty log data (not used for real TPMs)
func (t *transportCommandChannel) MeasurementLog() ([]byte, error) {
	return nil, nil
}

// Close closes the underlying TPM transport if it implements io.Closer
func (t *transportCommandChannel) Close() error {
	if closer, ok := t.tpm.(transport.TPMCloser); ok {
		return closer.Close()
	}
	return nil
}

// FromTransport creates a CommandChannelTPM20 from a transport.TPM
// forwarding commands to the underlying transport.TPM.
//
// Parameters:
//
//	tpm - the transport.TPM to be adapted
//
// Returns:
//
//	An implementation of attest.CommandChannelTPM20 that wraps the provided transport.TPM.
func FromTransport(tpm transport.TPM) attest.CommandChannelTPM20 {
	return &transportCommandChannel{tpm: tpm}
}
