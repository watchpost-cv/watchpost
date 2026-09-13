package cluster

import (
	"testing"
	"time"
)

func TestMemberHealthStates(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	seenNow := now.Add(-30 * time.Second)
	seenOld := now.Add(-3 * time.Minute)
	seenOffline := now.Add(-11 * time.Minute)
	cases := []struct {
		name string
		m    Member
		want string
	}{
		{"revoked", Member{State: "revoked", Compatible: true}, "revoked"},
		{"disabled", Member{State: "disabled", Compatible: true}, "disabled"},
		{"incompatible", Member{State: "active", Compatible: false}, "incompatible"},
		{"unknown", Member{State: "active", Compatible: true}, "unknown"},
		{"online", Member{State: "active", Compatible: true, LastSeenAt: &seenNow}, "online"},
		{"degraded", Member{State: "active", Compatible: true, LastSeenAt: &seenOld}, "degraded"},
		{"offline", Member{State: "active", Compatible: true, LastSeenAt: &seenOffline}, "offline"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := memberHealth(tc.m, now); got != tc.want {
				t.Fatalf("memberHealth()=%q want %q", got, tc.want)
			}
		})
	}
}
