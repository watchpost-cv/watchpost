package devices

import (
	"context"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/watchpost-cv/watchpost/internal/contract"
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

func TestReadingObservationContract(t *testing.T) {
	method := contract.Method{ID: "ups-poll", Kind: contract.MethodDeviceSNMP, PostID: "ups-1"}
	at := time.Now().UTC()
	numeric := Reading{Name: "battery_charge", OID: ".1.3.6.1.2.1.33.1.2.4.0", Unit: "percent", Value: int64(85), Quality: "good", ObservedAt: at, FreshUntil: at.Add(5 * time.Minute)}
	obs := numeric.Observation(method, at)
	if obs.Signal != "battery_charge" || obs.Value == nil || *obs.Value != 85 || obs.Quality != contract.QualityGood {
		t.Fatalf("numeric reading observation wrong: %#v", obs)
	}
	nonNumeric := Reading{Name: "model", OID: ".1.3.6.1.2.1.1.1.0", Unit: "string", Value: "SmartUPS", Quality: "good", ObservedAt: at, FreshUntil: at.Add(5 * time.Minute)}
	obs = nonNumeric.Observation(method, at)
	if obs.Value != nil {
		t.Fatalf("non-numeric reading gained a value: %#v", obs)
	}
	pollOK := PollOK(method, false, at)
	if pollOK.Signal != "snmp.poll_ok" || pollOK.Value == nil || *pollOK.Value != 0 || pollOK.Quality != contract.QualityGood {
		t.Fatalf("poll_ok observation wrong: %#v", pollOK)
	}
}
