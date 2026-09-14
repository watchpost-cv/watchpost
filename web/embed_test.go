package web

import (
	"os"
	"strings"
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

// TestApplicationNavigationHasNoCrossSiteLink is a regression test for a
// dogfooding-discovered defect: a request to add Gantry to the public-facing
// websites leaked a hard-coded https://gantry.cv link into the authenticated
// application navigation. The application menu must only carry application
// routes, never unsolicited cross-site branding.
func TestApplicationNavigationHasNoCrossSiteLink(t *testing.T) {
	b, err := os.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "gantry.cv") {
		t.Fatal("application frontend contains a hard-coded gantry.cv cross-site link; remove it from the Nift source and regenerate")
	}
}
