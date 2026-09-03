package web

import (
	"os"
	"testing"
)

// TestDistMatchesCanonicalSource guards the invariant that the committed SPA
// distribution is generated from canonical Nift source under web/content and
// web/templates. While the identity template holds, every tracked output is
// byte-identical to its content file. Edit the source and run `nift build` in
// the web directory, then commit the regenerated dist.
func TestDistMatchesCanonicalSource(t *testing.T) {
	for _, name := range []string{"index.html", "app.css", "app-extra.css", "script.js", "favicon.svg"} {
		content, err := os.ReadFile("content/" + name)
		if err != nil {
			t.Fatalf("%s: canonical source missing: %v", name, err)
		}
		dist, err := os.ReadFile("dist/" + name)
		if err != nil {
			t.Fatalf("%s: generated output missing: %v", name, err)
		}
		if string(dist) != string(content) {
			t.Errorf("%s: dist does not match canonical source; run `nift build` in web/ and commit the result", name)
		}
	}
}
