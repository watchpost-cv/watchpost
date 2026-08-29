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

// HostSignals is the canonical host signal registry. Both the installed agent
// and any bundled collector must emit exactly these names.
var HostSignals = []struct {
	Name, Unit, Range string
	Quality           string
	Labels            string
}{
	{"cpu.percent", "percent", "0-100", "good", "none"},
	{"memory.percent", "percent", "0-100", "good", "none"},
	{"disk.percent", "percent", "0-100", "good", "path=/ for the root filesystem"},
	{"filesystem.percent", "percent", "0-100", "good", "path=<filesystem>"},
	{"load.1", "load", "0+", "good", "none"},
	{"load.5", "load", "0+", "good", "none"},
	{"load.15", "load", "0+", "good", "none"},
	{"uptime.seconds", "seconds", "0+", "good", "none"},
	{"collector.up", "boolean", "0/1", "good", "none"},
}

// LegacySignalAliases maps deprecated signal names to their canonical names so
// existing rules and history keep working after a rename. Historical rows keep
// their original signal names; this is a bounded read/query alias, never a
// destructive rewrite.
var LegacySignalAliases = map[string]string{
	"load.one": "load.1",
}