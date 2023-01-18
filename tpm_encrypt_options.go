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

func CloseEmulatedDevice() { emulatedDevice.Close(); emulatedDevice = nil }

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

type TPMOption func(t *TPMOptions) error

func (t *TPMOptions) Apply(opts ...TPMOption) error {
	for _, o := range opts {
		if err := o(t); err != nil {
			return err
		}
	}

	return nil
}

var EmulatedTPM TPMOption = func(t *TPMOptions) error {
	t.emulated = true
	return nil
}

func WithHash(c crypto.Hash) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.hash = c
		return
	}
}

func WithPassword(s string) TPMOption {
	return func(t *TPMOptions) error {
		t.password = s
		return nil
	}
}

func WithDevice(s string) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.device = s
		return
	}
}

func WithAttributes(s string) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.keyAttr, err = parseKeyAttributes(s)
		return
	}
}

func WithIndex(s string) TPMOption {
	return func(t *TPMOptions) (err error) {
		t.index, err = parseHandle(s)
		return
	}
}

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
