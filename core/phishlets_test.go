package core

import (
	"os"
	"testing"
)

// loadPhishlet loads a phishlet by path with optional params.
// The test is skipped when the phishlet file does not exist in this checkout.
func loadPhishlet(t *testing.T, name, path string, params map[string]string) *Phishlet {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("phishlet file %q not found — skipping", path)
	}
	var p *map[string]string
	if params != nil {
		p = &params
	}
	pl, err := NewPhishlet(name, path, p, nil)
	if err != nil {
		t.Fatalf("phishlet %q load failed: %v", name, err)
	}
	return pl
}
