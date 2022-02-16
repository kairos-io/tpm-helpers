package backend

import (
	"io"
)

type FakeTPM struct {
	io.ReadWriteCloser
}

var fixedLog = []byte{0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x21, 0x0, 0x0, 0x0, 0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44,
	0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x2, 0x0, 0x2, 0x1, 0x0, 0x0, 0x0, 0xb, 0x0, 0x20, 0x0, 0x0}

func (*FakeTPM) MeasurementLog() ([]byte, error) { return fixedLog, nil }
