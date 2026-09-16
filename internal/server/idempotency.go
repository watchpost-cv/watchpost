package server

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/watchpost-cv/watchpost/internal/replicated"
)

// IdempotencyKeyHeader is the HTTP header carrying the caller-supplied
// idempotency/request identity for mutation requests. Retrying the SAME logical
// mutation with the SAME key maps to the SAME replication operation identity,
// so the durable operation-ID contract returns the original committed result
// (no second semantic mutation) for an identical retry and fails closed for a
// changed payload. A genuinely new intent uses a fresh key.
const IdempotencyKeyHeader = "X-Watchpost-Idempotency-Key"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// mutationContext derives the mutation context from the request, attaching the
// validated caller-supplied idempotency key when present.
func (s *Server) mutationContext(r *http.Request) (context.Context, error) {
	key := r.Header.Get(IdempotencyKeyHeader)
	if key == "" {
		return r.Context(), nil
	}
	if !requestIDPattern.MatchString(key) {
		return nil, fmt.Errorf("invalid idempotency key")
	}
	return replicated.WithRequestID(r.Context(), key), nil
}
