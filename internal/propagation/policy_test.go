package propagation

import (
	"encoding/json"
	core "github.com/gantry-tools/gantry-core/propagation"
	"testing"
)

func TestWatchpostKinds(t *testing.T) {
	e := core.Envelope{Kind: "monitor", ID: "m", SchemaVersion: 1, Revision: 1, SourceNode: "n", Target: "all", Conflict: core.ConflictReject, Actor: core.Actor{Permission: "monitor.update"}, Payload: json.RawMessage(`{"name":"x"}`)}
	if err := ValidateEnvelope(e); err != nil {
		t.Fatal(err)
	}
	e.Kind = "incident"
	if err := ValidateEnvelope(e); err == nil {
		t.Fatal("incident must remain node-local")
	}
}
