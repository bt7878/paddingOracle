package oracle

import "sync"

type Oracle struct {
	oracleFn func(ivAndCt []byte) bool
	calls    uint64
	mu       sync.Mutex
}

func NewOracle(oracleFn func(ivAndCt []byte) bool) *Oracle {
	return &Oracle{oracleFn: oracleFn}
}

func (o *Oracle) GetCalls() uint64 {
	return o.calls
}

func (o *Oracle) HasValidPadding(ivAndCt []byte) bool {
	o.mu.Lock()
	o.calls++
	o.mu.Unlock()

	return o.oracleFn(ivAndCt)
}
