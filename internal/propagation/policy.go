package propagation

import (
	"fmt"
	core "github.com/gantry-tools/gantry-core/propagation"
)

type KindPolicy struct {
	Kind       string
	Reversible bool
	Mergeable  bool
	Permission string
}

var policies = map[string]KindPolicy{
	"monitor":             {Kind: "monitor", Reversible: true, Permission: "monitor.update"},
	"alert-policy":        {Kind: "alert-policy", Reversible: true, Permission: "alert.update"},
	"notification-config": {Kind: "notification-config", Reversible: true, Permission: "notification.update"},
}

func Policy(kind string) (KindPolicy, bool) { p, ok := policies[kind]; return p, ok }
func ValidateEnvelope(e core.Envelope) error {
	p, ok := Policy(e.Kind)
	if !ok {
		return fmt.Errorf("watchpost propagation kind %q is not supported", e.Kind)
	}
	if e.Actor.Permission != "" && e.Actor.Permission != p.Permission {
		return fmt.Errorf("permission %q does not match %q", e.Actor.Permission, p.Permission)
	}
	return e.Validate()
}
func Kinds() []string {
	return []string{"alert-policy", "monitor", "notification-config"}
}
