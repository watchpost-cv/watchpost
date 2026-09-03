package web

import (
	"os"
	"testing"
)

// TestDistributionComplete verifies every embedded frontend file remains
// present. Reproducibility of tracked HTML is enforced by spa-gate.sh; CSS,
// JavaScript and image assets are maintained directly in dist.
func TestDistributionComplete(t *testing.T) {
	for _, name := range []string{"app.css", "app-extra.css", "script.js", "select-chevron.svg", "favicon.svg"} {
		if _, err := os.Stat("dist/" + name); err != nil {
			t.Errorf("%s: maintained distribution asset missing: %v", name, err)
		}
	}
	if _, err := os.Stat("dist/index.html"); err != nil {
		t.Errorf("index.html: generated distribution page missing: %v", err)
	}
}
