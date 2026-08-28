package devices

import "testing"

func TestSNMPAdapterIsReadOnly(t *testing.T) {
	v, err := Adapter("snmpv3")
	if err != nil {
		t.Fatal(err)
	}
	if v.Authority != "read_only" {
		t.Fatalf("authority=%s", v.Authority)
	}
	for _, capability := range v.Capabilities {
		if capability == "write" {
			t.Fatal("write capability exposed")
		}
	}
}
