package tpm

import (
	"github.com/folbricht/tpmk"
)

func StoreBlob(blob []byte, opts ...TPMOption) error {
	o, err := DefaultTPMOption(opts...)
	if err != nil {
		return err
	}

	// Open device or simulator
	dev, err := getTPMDevice(o)
	if err != nil {
		return err
	}
	if !o.emulated {
		defer dev.Close()
	}

	// Write to the index
	return tpmk.NVWrite(dev, o.index, blob, o.password, o.nvAttr)
}

func ReadBlob(opts ...TPMOption) ([]byte, error) {
	o, err := DefaultTPMOption(opts...)
	if err != nil {
		return []byte{}, err
	}

	// Open device or simulator
	dev, err := getTPMDevice(o)
	if err != nil {
		return []byte{}, err
	}
	if !o.emulated {
		defer dev.Close()
	}

	// Read the data
	return tpmk.NVRead(dev, o.index, o.password)
}
