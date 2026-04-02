package oracle

import "sync"

type Oracle struct {
	oracleFn func(ivAndCt []byte) (bool, error)
	calls    uint64
	mu       sync.Mutex
}

func NewOracle(oracleFn func(ivAndCt []byte) (bool, error)) *Oracle {
	return &Oracle{oracleFn: oracleFn}
}

func (o *Oracle) GetCalls() uint64 {
	return o.calls
}

func (o *Oracle) HasValidPadding(ivAndCt []byte) (bool, error) {
	o.mu.Lock()
	o.calls++
	o.mu.Unlock()

	return o.oracleFn(ivAndCt)
}
