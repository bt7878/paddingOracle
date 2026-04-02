package oracle

import (
	"sync/atomic"
)

type Oracle struct {
	oracleFn func(ivAndCt []byte) (bool, error)
	calls    atomic.Uint64
}

func NewOracle(oracleFn func(ivAndCt []byte) (bool, error)) *Oracle {
	return &Oracle{oracleFn: oracleFn}
}

func (o *Oracle) GetCalls() uint64 {
	return o.calls.Load()
}

func (o *Oracle) HasValidPadding(ivAndCt []byte) (bool, error) {
	o.calls.Add(1)

	return o.oracleFn(ivAndCt)
}
