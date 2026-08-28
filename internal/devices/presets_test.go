package devices

import "testing"

func TestInitialDevicePresetsStayBounded(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Presets() {
		seen[p.Kind] = true
		if len(p.OIDs) > 64 {
			t.Fatalf("%s too large", p.Kind)
		}
	}
	for _, kind := range []string{"network_device", "ups", "environmental_sensor", "storage_appliance"} {
		if !seen[kind] {
			t.Fatalf("missing %s", kind)
		}
	}
}
