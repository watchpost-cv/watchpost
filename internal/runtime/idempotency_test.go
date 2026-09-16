package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost/internal/replicated"
	"github.com/watchpost-cv/watchpost/internal/server"
)

// httpPostKey drives the authenticated HTTP create-post path with a caller
// idempotency key header, mirroring an ambiguous-response retry at the real
// HTTP boundary.
func httpPostKey(t *testing.T, client *http.Client, baseURL, key string, body any) (int, []byte) {
	t.Helper()
	do := func(method, path string, payload any, cookie *http.Cookie, csrf, idem string) (*http.Response, []byte) {
		var rd io.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, baseURL+path, rd)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-Watchpost-CSRF", csrf)
		}
		if idem != "" {
			req.Header.Set(server.IdempotencyKeyHeader, idem)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	_, _ = do("POST", "/api/v1/setup", map[string]string{"username": "admin", "email": "admin@example.com", "password": "1234567"}, nil, "", "")
	login, lb := do("POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "", "")
	cookie := login.Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(lb, &session)
	resp, rb := do("POST", "/api/v1/posts", body, cookie, session.CSRF, key)
	return resp.StatusCode, rb
}

func postVersion(t *testing.T, n *node, id string) int {
	t.Helper()
	var v int
	if err := n.store.DB.QueryRow(`SELECT version FROM posts WHERE id=?`, id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestHTTPIdempotencyDirectLeader proves the ambiguous-response case at the
// leader HTTP boundary: retrying the SAME logical mutation with the SAME
// request identity returns the original committed result with ONE semantic
// mutation; retrying with the SAME identity but a DIFFERENT payload fails
// closed and leaves state unchanged.
func TestHTTPIdempotencyDirectLeader(t *testing.T) {
	ca := newTestCA(t)
	n := newNode(t, ca, t.TempDir(), "A", nil, true, 0, true, "")
	waitReadiness(t, n, replicated.ReadinessReadyLeader)

	body := map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}}
	if code, _ := httpPostKey(t, n.http.Client(), n.http.URL, "req-create-1", body); code != http.StatusCreated {
		t.Fatalf("first create: %d", code)
	}
	// Simulated response loss / ambiguity: the client retries the same mutation.
	if code, _ := httpPostKey(t, n.http.Client(), n.http.URL, "req-create-1", body); code != http.StatusCreated {
		t.Fatalf("ambiguous retry must return the original committed result: %d", code)
	}
	if countPosts(t, n, "host-a") != 1 {
		t.Fatal("ambiguous retry produced a second semantic mutation")
	}
	if v := postVersion(t, n, "host-a"); v != 1 {
		t.Fatalf("ambiguous retry changed the committed result: version=%d want 1", v)
	}

	// Same identity, different semantic payload -> fail closed.
	changed := map[string]any{"id": "host-a", "name": "Host A CHANGED", "kind": "host", "labels": map[string]string{}}
	if code, _ := httpPostKey(t, n.http.Client(), n.http.URL, "req-create-1", changed); code == http.StatusCreated {
		t.Fatal("same identity with different payload must fail closed")
	}
	if countPosts(t, n, "host-a") != 1 {
		t.Fatal("fail-closed retry mutated state")
	}
	if v := postVersion(t, n, "host-a"); v != 1 {
		t.Fatalf("fail-closed retry changed state: version=%d", v)
	}
	if got := queryPostName(t, n, "host-a"); got != "Host A" {
		t.Fatalf("fail-closed retry changed the name: %q", got)
	}
}

func queryPostName(t *testing.T, n *node, id string) string {
	t.Helper()
	var name string
	if err := n.store.DB.QueryRow(`SELECT name FROM posts WHERE id=?`, id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

// TestHTTPIdempotencyFollowerForwarded proves the request identity survives the
// follower path: HTTP -> follower -> ForwardClient -> leader RPC -> Adapter ->
// Raft. An ambiguous retry through the follower deduplicates on the leader.
func TestHTTPIdempotencyFollowerForwarded(t *testing.T) {
	ca := newTestCA(t)
	const aToB, bToA = "A_to_B", "B_to_A"
	a := newNode(t, ca, t.TempDir(), "A", map[string][2]string{"B": {aToB, bToA}}, true, 0, true, freeAddr(t))
	b := newNode(t, ca, t.TempDir(), "B", map[string][2]string{"A": {bToA, aToB}}, false, 0, true, freeAddr(t))
	waitReadiness(t, a, replicated.ReadinessReadyLeader)
	if err := a.repl.Node.AddVoter("B", b.repl.Node.Address()); err != nil {
		t.Fatalf("join B: %v", err)
	}
	setPublicEndpoint(t, a.store.DB, "B", b.http.URL)
	setPublicEndpoint(t, b.store.DB, "A", a.http.URL)
	waitReadiness(t, b, replicated.ReadinessReadyFollower)

	body := map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}}
	if code, _ := httpPostKey(t, b.http.Client(), b.http.URL, "req-fwd-1", body); code != http.StatusCreated {
		t.Fatalf("first follower create: %d", code)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1) {
		time.Sleep(20 * time.Millisecond)
	}
	if countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1 {
		t.Fatalf("forwarded mutation did not converge: A=%d B=%d", countPosts(t, a, "host-a"), countPosts(t, b, "host-a"))
	}

	// Ambiguous retry through the follower with the same identity.
	if code, _ := httpPostKey(t, b.http.Client(), b.http.URL, "req-fwd-1", body); code != http.StatusCreated {
		t.Fatalf("follower ambiguous retry must return the committed result: %d", code)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1) {
		time.Sleep(20 * time.Millisecond)
	}
	if countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1 {
		t.Fatalf("follower ambiguous retry produced a second mutation: A=%d B=%d", countPosts(t, a, "host-a"), countPosts(t, b, "host-a"))
	}
	if v := postVersion(t, a, "host-a"); v != 1 {
		t.Fatalf("follower retry changed the committed result: version=%d want 1", v)
	}
}

// TestHTTPIdempotencyInvalidKeyRejected proves an invalid idempotency key is
// rejected (fail closed) rather than silently accepted.
func TestHTTPIdempotencyInvalidKeyRejected(t *testing.T) {
	ca := newTestCA(t)
	n := newNode(t, ca, t.TempDir(), "A", nil, true, 0, true, "")
	waitReadiness(t, n, replicated.ReadinessReadyLeader)
	code, _ := httpPostKey(t, n.http.Client(), n.http.URL, "bad key with spaces!", map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}})
	if code != http.StatusBadRequest {
		t.Fatalf("invalid idempotency key: status %d want 400", code)
	}
	if countPosts(t, n, "host-a") != 0 {
		t.Fatal("invalid-key request mutated state")
	}
}

// httpPutKey performs an authenticated post update with an idempotency key and
// an If-Match precondition.
func httpPutKey(t *testing.T, client *http.Client, baseURL, id, key string, ifMatch int, body any) int {
	t.Helper()
	do := func(method, path string, payload any, cookie *http.Cookie, csrf, idem, ifm string) (*http.Response, []byte) {
		var rd io.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, baseURL+path, rd)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-Watchpost-CSRF", csrf)
		}
		if idem != "" {
			req.Header.Set(server.IdempotencyKeyHeader, idem)
		}
		if ifm != "" {
			req.Header.Set("If-Match", ifm)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	_, _ = do("POST", "/api/v1/setup", map[string]string{"username": "admin", "email": "admin@example.com", "password": "1234567"}, nil, "", "", "")
	login, lb := do("POST", "/api/v1/login", map[string]string{"email": "admin@example.com", "password": "1234567"}, nil, "", "", "")
	cookie := login.Cookies()[0]
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(lb, &session)
	resp, _ := do("PUT", "/api/v1/posts/"+id, body, cookie, session.CSRF, key, fmt.Sprint(ifMatch))
	return resp.StatusCode
}

// TestHTTPIdempotencyPostUpdatePrecondition proves an update retry with the
// SAME request identity and SAME If-Match precondition deduplicates, while the
// SAME identity with a DIFFERENT precondition fails closed.
func TestHTTPIdempotencyPostUpdatePrecondition(t *testing.T) {
	ca := newTestCA(t)
	n := newNode(t, ca, t.TempDir(), "A", nil, true, 0, true, "")
	waitReadiness(t, n, replicated.ReadinessReadyLeader)
	if code, _ := httpPostKey(t, n.http.Client(), n.http.URL, "req-create-a", map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}}); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	update := map[string]any{"id": "host-a", "name": "Host A v2", "kind": "host", "labels": map[string]string{}}
	if code := httpPutKey(t, n.http.Client(), n.http.URL, "host-a", "req-update-1", 1, update); code != http.StatusOK {
		t.Fatalf("first update: %d", code)
	}
	if v := postVersion(t, n, "host-a"); v != 2 {
		t.Fatalf("post version=%d want 2", v)
	}
	// Ambiguous retry: same identity, same precondition -> dedup, no version bump.
	if code := httpPutKey(t, n.http.Client(), n.http.URL, "host-a", "req-update-1", 1, update); code != http.StatusOK {
		t.Fatalf("ambiguous update retry: %d", code)
	}
	if v := postVersion(t, n, "host-a"); v != 2 {
		t.Fatalf("ambiguous update retry bumped version: %d", v)
	}
	// Same identity, different precondition (If-Match 2) -> fail closed.
	if code := httpPutKey(t, n.http.Client(), n.http.URL, "host-a", "req-update-1", 2, update); code == http.StatusOK {
		t.Fatal("same identity with different precondition must fail closed")
	}
	if v := postVersion(t, n, "host-a"); v != 2 {
		t.Fatalf("fail-closed retry changed state: version=%d", v)
	}
}

// TestHTTPIdempotencyAcrossLeadershipChange proves the ambiguous-response retry
// contract across an ACTUAL leadership transition: operation R committed under
// leader A, response treated as lost, A forced out of leadership, and the SAME
// logical mutation retried against the new leader B. B recognizes the committed
// operation identity (reconstructed from its applied state), returns the
// original committed result, and does not create a second semantic mutation.
func TestHTTPIdempotencyAcrossLeadershipChange(t *testing.T) {
	ca := newTestCA(t)
	const aToB, bToA = "A_to_B", "B_to_A"
	a := newNode(t, ca, t.TempDir(), "A", map[string][2]string{"B": {aToB, bToA}}, true, 0, true, freeAddr(t))
	b := newNode(t, ca, t.TempDir(), "B", map[string][2]string{"A": {bToA, aToB}}, false, 0, true, freeAddr(t))
	waitReadiness(t, a, replicated.ReadinessReadyLeader)
	if err := a.repl.Node.AddVoter("B", b.repl.Node.Address()); err != nil {
		t.Fatalf("join B: %v", err)
	}
	setPublicEndpoint(t, a.store.DB, "B", b.http.URL)
	setPublicEndpoint(t, b.store.DB, "A", a.http.URL)
	waitReadiness(t, b, replicated.ReadinessReadyFollower)

	// 1. Commit operation "leader-change-1" through leader A.
	body := map[string]any{"id": "host-a", "name": "Host A", "kind": "host", "labels": map[string]string{}}
	if code, _ := httpPostKey(t, a.http.Client(), a.http.URL, "leader-change-1", body); code != http.StatusCreated {
		t.Fatalf("commit through A: %d", code)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1) {
		time.Sleep(20 * time.Millisecond)
	}
	if countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1 {
		t.Fatalf("initial commit did not converge: A=%d B=%d", countPosts(t, a, "host-a"), countPosts(t, b, "host-a"))
	}
	if _, ok := b.repl.FSM.OpKnown("leader-change-1"); !ok {
		t.Fatal("follower B did not learn the committed operation identity")
	}

	// 2. Force A out of leadership; the new leader is B.
	if err := a.repl.Node.LeadershipTransfer(); err != nil {
		t.Fatalf("leadership transfer: %v", err)
	}
	waitReadiness(t, b, replicated.ReadinessReadyLeader)

	// 3. Ambiguous retry of the SAME logical mutation against the NEW leader B.
	if code, _ := httpPostKey(t, b.http.Client(), b.http.URL, "leader-change-1", body); code != http.StatusCreated {
		t.Fatalf("retry against new leader: %d", code)
	}

	// 4. Exactly one semantic mutation; version unchanged; new leader recognizes
	// the committed operation identity (not treated as new intent).
	if countPosts(t, a, "host-a") != 1 || countPosts(t, b, "host-a") != 1 {
		t.Fatalf("leader-change retry produced a second mutation: A=%d B=%d", countPosts(t, a, "host-a"), countPosts(t, b, "host-a"))
	}
	if v := postVersion(t, b, "host-a"); v != 1 {
		t.Fatalf("leader-change retry changed the committed result: version=%d want 1", v)
	}
	if _, ok := b.repl.FSM.OpKnown("leader-change-1"); !ok {
		t.Fatal("new leader must recognize the committed operation identity")
	}

	// 5. Same identity + DIFFERENT semantic payload after the leader change must
	// fail closed with original state unchanged.
	changed := map[string]any{"id": "host-a", "name": "Host A CHANGED", "kind": "host", "labels": map[string]string{}}
	if code, _ := httpPostKey(t, b.http.Client(), b.http.URL, "leader-change-1", changed); code == http.StatusCreated {
		t.Fatal("same identity with different payload after leader change must fail closed")
	}
	if countPosts(t, b, "host-a") != 1 {
		t.Fatal("rejected leader-change retry mutated state")
	}
	if v := postVersion(t, b, "host-a"); v != 1 {
		t.Fatalf("rejected leader-change retry changed state: version=%d", v)
	}
	if got := queryPostName(t, b, "host-a"); got != "Host A" {
		t.Fatalf("rejected leader-change retry changed the name: %q", got)
	}
}
