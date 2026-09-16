package replicated

import (
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/gantry-tools/gantry-core/replication"
	"github.com/hashicorp/raft"
)

func newBareFSM(t *testing.T) (*FSM, *sql.DB) {
	t.Helper()
	db := openTestDB(t)
	fsm, err := NewFSM(db)
	if err != nil {
		t.Fatal(err)
	}
	return fsm, db
}

// applyCommitted feeds a raw committed log entry directly to the FSM (the same
// boundary raft.FSM.Apply runs for committed history), bypassing proposal-time
// validation so the committed-entry failure classification is exercised.
func applyCommitted(fsm *FSM, index uint64, raw []byte) interface{} {
	return fsm.Apply(&raft.Log{Index: index, Term: 1, Type: raft.LogCommand, Data: raw})
}

// TestCommittedUnsupportedKindPoisonsFSM proves a committed entry with an
// unsupported Watchpost operation kind poisons the FSM: sticky unhealthy, the
// later valid committed entry is fenced, nothing materializes, the applied
// position and op-ID state do not advance.
func TestCommittedUnsupportedKindPoisonsFSM(t *testing.T) {
	fsm, db := newBareFSM(t)
	op := replication.Operation{ID: "bad-kind", Product: "watchpost", Version: 2, Kind: "bogus_kind", ObjectID: "p1", Payload: json.RawMessage(`{"name":"x"}`)}
	raw, _ := json.Marshal(op)
	if res := applyCommitted(fsm, 2, raw); res == nil {
		t.Fatal("committed unsupported-kind entry must fail")
	}
	if fsm.ApplyFailure() == nil {
		t.Fatal("committed unsupported-kind entry must poison the FSM")
	}
	good, err := buildOperation("post-good", "watchpost", KindPostCreate, "p2", 0, 0, mkPost("g", "host"))
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := good.Encode()
	if res := applyCommitted(fsm, 3, raw2); res == nil {
		t.Fatal("later committed valid entry must be fenced")
	}
	if got := count(t, db, `SELECT COUNT(*) FROM posts`); got != 0 {
		t.Fatalf("product mutated after committed-entry failure: %d", got)
	}
	if idx, _ := fsm.AppliedIndex(); idx != 0 {
		t.Fatalf("applied position advanced past the failure: %d", idx)
	}
	if _, ok := fsm.OpKnown("bad-kind"); ok {
		t.Fatal("failed operation entered successful op-ID state")
	}
	if _, ok := fsm.OpKnown("post-good"); ok {
		t.Fatal("fenced later operation entered successful op-ID state")
	}
}

// TestCommittedMalformedPayloadPoisonsFSM proves a committed entry whose
// payload cannot be canonicalized (Digest failure) poisons the FSM and fences
// every later committed entry.
func TestCommittedMalformedPayloadPoisonsFSM(t *testing.T) {
	fsm, db := newBareFSM(t)
	op := replication.Operation{ID: "bad-payload", Product: "watchpost", Version: 2, Kind: KindPostCreate, ObjectID: "p1", Payload: json.RawMessage(`{invalid`)}
	raw, _ := json.Marshal(op)
	if res := applyCommitted(fsm, 2, raw); res == nil {
		t.Fatal("committed malformed-payload entry must fail")
	}
	if fsm.ApplyFailure() == nil {
		t.Fatal("committed digest failure must poison the FSM")
	}
	good, err := buildOperation("post-good", "watchpost", KindPostCreate, "p2", 0, 0, mkPost("g", "host"))
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := good.Encode()
	if res := applyCommitted(fsm, 3, raw2); res == nil {
		t.Fatal("later committed valid entry must be fenced")
	}
	if got := count(t, db, `SELECT COUNT(*) FROM posts`); got != 0 {
		t.Fatalf("product mutated after committed-entry failure: %d", got)
	}
	if idx, _ := fsm.AppliedIndex(); idx != 0 {
		t.Fatalf("applied position advanced past the failure: %d", idx)
	}
	if _, ok := fsm.OpKnown("bad-payload"); ok {
		t.Fatal("failed operation entered successful op-ID state")
	}
	if _, ok := fsm.OpKnown("post-good"); ok {
		t.Fatal("fenced later operation entered successful op-ID state")
	}
}

// TestCommittedUnsupportedLocalVersionPoisonsFSM proves a committed entry at a
// version the local FSM cannot realize (an older local node replaying newer
// committed history) poisons the FSM and fences later entries.
func TestCommittedUnsupportedLocalVersionPoisonsFSM(t *testing.T) {
	fsm, db := newBareFSM(t)
	fsm.supported = 1 // older local FSM: cannot realize schema 2
	op, err := buildOperation("post-v", "watchpost", KindPostCreate, "p1", 0, 0, mkPost("x", "host"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := op.Encode()
	if res := applyCommitted(fsm, 2, raw); res == nil {
		t.Fatal("committed unsupported-local-version entry must fail")
	}
	if fsm.ApplyFailure() == nil {
		t.Fatal("committed unsupported-local-version entry must poison the FSM")
	}
	// A later version-1 entry (supported locally) must still be fenced: the
	// failed committed position is the reconciliation boundary.
	op1 := op
	op1.ID = "post-v1"
	op1.Version = 1
	raw2, _ := json.Marshal(op1)
	if res := applyCommitted(fsm, 3, raw2); res == nil {
		t.Fatal("later committed entry must be fenced")
	}
	if got := count(t, db, `SELECT COUNT(*) FROM posts`); got != 0 {
		t.Fatalf("product mutated after committed-entry failure: %d", got)
	}
	if idx, _ := fsm.AppliedIndex(); idx != 0 {
		t.Fatalf("applied position advanced past the failure: %d", idx)
	}
}
