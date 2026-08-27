package devices

import (
	"context"
	"github.com/gosnmp/gosnmp"
	"testing"
)

type fakeGetter struct{}

func (fakeGetter) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	return &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{Name: oids[0], Type: gosnmp.Counter64, Value: uint64(42)}}}, nil
}
func TestBoundedProfilePoll(t *testing.T) {
	profile := Profile{ID: "switch", Kind: "network_device", OIDs: []OID{{Name: "interface.bytes", OID: "1.2.3", Unit: "bytes"}}}
	if err := ValidateProfile(profile); err != nil {
		t.Fatal(err)
	}
	readings, err := Poll(context.Background(), fakeGetter{}, profile)
	if err != nil || len(readings) != 1 || readings[0].Quality != "good" {
		t.Fatalf("%#v %v", readings, err)
	}
}
func TestV3RequiresAuthPriv(t *testing.T) {
	if _, err := NewV3(V3Config{Address: "router"}); err == nil {
		t.Fatal("weak credentials accepted")
	}
}
