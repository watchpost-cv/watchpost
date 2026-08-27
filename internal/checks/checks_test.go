package checks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPAndTCPChecks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	runner := New(time.Second)
	if got := runner.HTTPCheck(context.Background(), server.URL); !got.OK || got.Status != 204 {
		t.Fatalf("%#v", got)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if got := runner.TCP(context.Background(), listener.Addr().String()); !got.OK {
		t.Fatalf("%#v", got)
	}
}
func TestPublicAddress(t *testing.T) {
	if PublicAddress("127.0.0.1") || PublicAddress("10.0.0.1") || !PublicAddress("8.8.8.8") {
		t.Fatal("address classification")
	}
}
