// Package contract freezes the canonical monitoring-method, source and
// observation envelope every monitoring method must produce. Agent host
// collectors, central HTTP/TCP/TLS/DNS/ICMP checks and device adapters
// (currently SNMP) all converge on this shape before later checkpoints route
// their results through the rule and survey pipeline.
//
// This package is deliberately behaviour-neutral: it pins types and
// invariants only. Wiring methods through the pipeline happens in later
// checkpoints.
package contract

import "time"

// ProtocolVersion is the canonical observation contract version.
const ProtocolVersion = 1

// Quality is the explicit observation-quality vocabulary. Missing and stale
// are distinct states and are never converted to numeric zero.
type Quality string

const (
	QualityGood      Quality = "good"
	QualityUncertain Quality = "uncertain"
	QualityBad       Quality = "bad"
	QualityMissing   Quality = "missing"
	QualityStale     Quality = "stale"
)

// MethodKind is the closed set of monitoring methods.
type MethodKind string

const (
	MethodHostAgent    MethodKind = "host_agent"    // separately installed host collectors
	MethodCentralCheck MethodKind = "central_check" // centrally scheduled HTTP/TCP/TLS/DNS/ICMP
	MethodDeviceSNMP   MethodKind = "device_snmp"   // read-only device adapter polling
)

// Method identifies how a post is observed. Identity is durable and stable;
// kind-specific configuration lives in the owning store (check schedules,
// device profiles, agent state).
type Method struct {
	ID     string
	Kind   MethodKind
	PostID string
}

// Source identifies the concrete collector or probe within a method that
// produced an observation. Identity is the durable credential-owning id.
// Hostname and address are descriptive metadata only and are never treated as
// identity.
type Source struct {
	Method   Method
	Identity string
	Hostname string
}

// Observation is the canonical envelope every monitoring method produces.
// Quality and freshness are explicit; a missing reading is a missing reading.
type Observation struct {
	Version    int
	PostID     string
	Source     Source
	Signal     string
	Value      *float64
	Unit       string
	Quality    Quality
	Labels     map[string]string
	ObservedAt time.Time
	IngestedAt time.Time
	FreshUntil time.Time
}