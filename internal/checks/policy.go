package checks

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Policy restricts which targets may be probed. Monitoring internal
// infrastructure is a core feature, so a zero-valued policy allows everything;
// operators opt into CIDR and port allow/deny lists.
type Policy struct {
	allows    []*net.IPNet
	denies    []*net.IPNet
	denyPorts map[int]bool
	resolver  *net.Resolver
}

// NewPolicy parses CIDR strings and deny ports. Empty allow/deny lists mean
// "allow everything".
func NewPolicy(allowCIDRs, denyCIDRs []string, denyPorts []int) (*Policy, error) {
	policy := &Policy{denyPorts: map[int]bool{}, resolver: net.DefaultResolver}
	parse := func(values []string) ([]*net.IPNet, error) {
		nets := []*net.IPNet{}
		for _, value := range values {
			_, network, err := net.ParseCIDR(strings.TrimSpace(value))
			if err != nil {
				return nil, fmt.Errorf("invalid check-policy CIDR %q", value)
			}
			nets = append(nets, network)
		}
		return nets, nil
	}
	var err error
	if policy.allows, err = parse(allowCIDRs); err != nil {
		return nil, err
	}
	if policy.denies, err = parse(denyCIDRs); err != nil {
		return nil, err
	}
	for _, port := range denyPorts {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid denied port %d", port)
		}
		policy.denyPorts[port] = true
	}
	return policy, nil
}

// Validate resolves the target and applies allow/deny CIDR and port rules. The
// port is derived from the host when it carries a port suffix, or supplied
// explicitly. An unresolvable hostname is not a policy denial: the check will
// report the resolution failure itself.
func (p *Policy) Validate(ctx context.Context, host string, port int) error {
	if p == nil {
		return nil
	}
	host = strings.TrimSpace(host)
	if parsed, err := url.Parse(host); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		host = parsed.Host
	}
	host = strings.Trim(host, "[]")
	parsedHost, parsedPort := splitHostPort(host)
	if parsedPort != 0 {
		host = parsedHost
		port = parsedPort
	}
	if p.denyPorts[port] {
		return fmt.Errorf("target port %d denied by check policy", port)
	}
	if p.allows == nil && p.denies == nil {
		return nil
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := p.resolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		// Unresolvable names are a check failure, not a policy denial.
		return nil
	}
	for _, entry := range ips {
		ip := entry.IP
		if ip == nil {
			continue
		}
		if policyMatches(p.denies, ip) {
			return fmt.Errorf("target %s denied by check policy", ip)
		}
		if len(p.allows) > 0 && !policyMatches(p.allows, ip) {
			return fmt.Errorf("target %s not allowed by check policy", ip)
		}
	}
	return nil
}

func policyMatches(nets []*net.IPNet, ip net.IP) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// splitHostPort extracts a numeric port from a host:port or [v6]:port value.
func splitHostPort(value string) (string, int) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return value, 0
	}
	parsed, err := strconv.Atoi(port)
	if err != nil {
		return value, 0
	}
	return host, parsed
}
