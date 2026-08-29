package checks

import (
	"context"
	"testing"
)

func TestPolicyAllowsEverythingByDefault(t *testing.T) {
	policy, err := NewPolicy(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "8.8.8.8", "example.com:443"} {
		if err := policy.Validate(context.Background(), host, 0); err != nil {
			t.Fatalf("default policy denied %s: %v", host, err)
		}
	}
}

func TestPolicyDenyCIDRBlocksPrivateTarget(t *testing.T) {
	policy, err := NewPolicy(nil, []string{"10.0.0.0/8", "127.0.0.0/8"}, []int{})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(context.Background(), "10.0.0.5", 0); err == nil {
		t.Fatal("denied 10.x target passed policy")
	}
	if err := policy.Validate(context.Background(), "127.0.0.1", 0); err == nil {
		t.Fatal("denied loopback target passed policy")
	}
	if err := policy.Validate(context.Background(), "8.8.8.8", 0); err != nil {
		t.Fatalf("public target denied: %v", err)
	}
}

func TestPolicyDenyCIDRBlocksResolvedHostname(t *testing.T) {
	// "localhost" resolves to 127.0.0.1; the deny rule on 127.0.0.0/8 must
	// catch it, proving policy is applied to resolved addresses (DNS-rebinding
	// defence) rather than the literal name.
	policy, err := NewPolicy(nil, []string{"127.0.0.0/8"}, []int{})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(context.Background(), "localhost", 0); err == nil {
		t.Fatal("localhost resolving to a denied loopback address passed policy")
	}
}

func TestPolicyAllowCIDROnlyAllowsListedTargets(t *testing.T) {
	policy, err := NewPolicy([]string{"10.0.0.0/8"}, nil, []int{})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(context.Background(), "10.0.0.5", 0); err != nil {
		t.Fatalf("listed target denied: %v", err)
	}
	if err := policy.Validate(context.Background(), "8.8.8.8", 0); err == nil {
		t.Fatal("unlisted target passed allow-only policy")
	}
}

func TestPolicyDeniesPorts(t *testing.T) {
	policy, err := NewPolicy(nil, nil, []int{22})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(context.Background(), "10.0.0.5:22", 0); err == nil {
		t.Fatal("denied port 22 passed policy")
	}
	if err := policy.Validate(context.Background(), "10.0.0.5", 22); err == nil {
		t.Fatal("denied explicit port 22 passed policy")
	}
	if err := policy.Validate(context.Background(), "10.0.0.5:443", 0); err != nil {
		t.Fatalf("allowed port denied: %v", err)
	}
}

func TestPolicyRejectsInvalidCIDR(t *testing.T) {
	if _, err := NewPolicy(nil, []string{"not-a-cidr"}, nil); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}
