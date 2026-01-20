//go:build nyx

package smite

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// NyxRunner interfaces with the Nyx hypervisor for fuzzing.
// It retrieves fuzz inputs from the Nyx agent and reports test results.
type NyxRunner struct {
	maxInputSize int
}

// NewNyxRunner creates a new NyxRunner instance and initializes the Nyx agent.
func NewNyxRunner() (*NyxRunner, error) {
	maxInputSize := nyxInit()
	if maxInputSize == 0 {
		return nil, fmt.Errorf("failed to initialize Nyx agent")
	}

	// The nyx agent, written in C, uses `setenv()` which will not affect Go's
	// `os.Environ`. Sync the variables set by the agent, such that they are
	// present in `os.Environ` to ensure that processes launched through
	// `exec.Command` inherit them.
	syncAFLVars()

	return &NyxRunner{
		maxInputSize: maxInputSize,
	}, nil
}

// GetFuzzInput retrieves the next fuzz input from the Nyx agent.
// Note: This takes a VM snapshot on the first call.
func (r *NyxRunner) GetFuzzInput() []byte {
	buffer := make([]byte, r.maxInputSize)
	inputLen := nyxGetFuzzInput(buffer, r.maxInputSize)
	return buffer[:inputLen]
}

// Fail reports a crash to the Nyx agent with the given error message.
func (r *NyxRunner) Fail(message string) {
	nyxFail(message)
}

// Skip skips the current test case by resetting the coverage bitmap
// and VM state.
func (r *NyxRunner) Skip() {
	nyxSkip()
}

// Close releases the Nyx agent, resetting the VM to the snapshot state.
// This should be called after successfully processing a test case.
func (r *NyxRunner) Close() error {
	nyxRelease()
	return nil
}

// MaxInputSize returns the maximum size for fuzz inputs.
func (r *NyxRunner) MaxInputSize() int {
	return r.maxInputSize
}

func syncAFLVars() {
	keys := []string{"__AFL_SHM_ID", "AFL_MAP_SIZE"}

	for _, key := range keys {
		cKey := C.CString(key)
		valPtr := C.getenv(cKey)
		C.free(unsafe.Pointer(cKey))

		if valPtr != nil {
			val := C.GoString(valPtr)
			os.Setenv(key, val)
		}
	}
}
