package domain

import "testing"

func TestCanonicalPostKindsAndQualityAreStable(t *testing.T) {
	kinds := []PostKind{PostKindHost, PostKindHTTPEndpoint, PostKindTCPService, PostKindTLSCert}
	quality := []Quality{QualityGood, QualityUncertain, QualityBad, QualityMissing, QualityStale}
	seen := map[string]bool{}
	for _, value := range kinds {
		if value == "" || seen[string(value)] {
			t.Fatalf("invalid kind %q", value)
		}
		seen[string(value)] = true
	}
	for _, value := range quality {
		if value == "" || seen[string(value)] {
			t.Fatalf("invalid quality %q", value)
		}
		seen[string(value)] = true
	}
}
