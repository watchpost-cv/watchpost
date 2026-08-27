package host

import (
	"runtime"
	"testing"
)

func TestCollectLinuxHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip()
	}
	s, err := Collect()
	if err != nil {
		t.Fatal(err)
	}
	if s.MemoryTotal == 0 || s.UptimeSeconds <= 0 || s.ObservedAt.IsZero() {
		t.Fatalf("incomplete snapshot: %#v", s)
	}
}
