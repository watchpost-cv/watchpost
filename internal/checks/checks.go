package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Result struct {
	Kind      string        `json:"kind"`
	Address   string        `json:"address"`
	OK        bool          `json:"ok"`
	Latency   time.Duration `json:"latency"`
	Status    int           `json:"status,omitempty"`
	ExpiresAt *time.Time    `json:"expires_at,omitempty"`
	Failure   string        `json:"failure,omitempty"`
}
type Runner struct {
	Resolver *net.Resolver
	Dialer   *net.Dialer
	HTTP     *http.Client
}

func New(timeout time.Duration) *Runner {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: timeout, MaxIdleConns: 10}
	return &Runner{Resolver: net.DefaultResolver, Dialer: dialer, HTTP: &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		if len(via) > 0 && req.URL.Hostname() != via[0].URL.Hostname() {
			return fmt.Errorf("cross-host redirect refused")
		}
		return nil
	}}}
}
func (r *Runner) Run(ctx context.Context, kind, address, serverName string) Result {
	switch kind {
	case "http":
		return r.HTTPCheck(ctx, address)
	case "tcp":
		return r.TCP(ctx, address)
	case "tls":
		return r.TLS(ctx, address, serverName)
	case "dns":
		return r.DNS(ctx, address)
	case "icmp":
		return r.ICMP(ctx, address)
	default:
		return Result{Kind: kind, Address: address, Failure: "unsupported check"}
	}
}
func (r *Runner) TCP(ctx context.Context, address string) Result {
	start := time.Now()
	conn, err := r.Dialer.DialContext(ctx, "tcp", address)
	result := Result{Kind: "tcp", Address: address, Latency: time.Since(start)}
	if err != nil {
		result.Failure = err.Error()
		return result
	}
	conn.Close()
	result.OK = true
	return result
}
func (r *Runner) DNS(ctx context.Context, name string) Result {
	start := time.Now()
	ips, err := r.Resolver.LookupHost(ctx, name)
	result := Result{Kind: "dns", Address: name, Latency: time.Since(start)}
	if err != nil || len(ips) == 0 {
		if err != nil {
			result.Failure = err.Error()
		} else {
			result.Failure = "no addresses"
		}
		return result
	}
	result.OK = true
	return result
}
func (r *Runner) ICMP(ctx context.Context, address string) Result {
	start := time.Now()
	result := Result{Kind: "icmp", Address: address}
	ips, err := r.Resolver.LookupIP(ctx, "ip4", address)
	if err != nil || len(ips) == 0 {
		result.Failure = "resolve ICMP address"
		return result
	}
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		result.Failure = "ICMP unavailable: " + err.Error()
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(r.Dialer.Timeout))
	message := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: int(time.Now().UnixNano() & 0xffff), Seq: 1, Data: []byte("watchpost")}}
	payload, _ := message.Marshal(nil)
	if _, err = conn.WriteTo(payload, &net.UDPAddr{IP: ips[0]}); err != nil {
		result.Failure = err.Error()
		return result
	}
	buffer := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buffer)
	result.Latency = time.Since(start)
	if err != nil {
		result.Failure = err.Error()
		return result
	}
	reply, err := icmp.ParseMessage(1, buffer[:n])
	if err != nil || reply.Type != ipv4.ICMPTypeEchoReply {
		result.Failure = "invalid ICMP reply"
		return result
	}
	result.OK = true
	return result
}
func (r *Runner) HTTPCheck(ctx context.Context, address string) Result {
	start := time.Now()
	result := Result{Kind: "http", Address: address}
	parsed, err := url.Parse(address)
	if err != nil || !(parsed.Scheme == "http" || parsed.Scheme == "https") || parsed.Host == "" {
		result.Failure = "invalid HTTP URL"
		return result
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	response, err := r.HTTP.Do(request)
	result.Latency = time.Since(start)
	if err != nil {
		result.Failure = err.Error()
		return result
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	result.Status = response.StatusCode
	result.OK = response.StatusCode >= 200 && response.StatusCode < 400
	return result
}
func (r *Runner) TLS(ctx context.Context, address, serverName string) Result {
	start := time.Now()
	dialer := tls.Dialer{NetDialer: r.Dialer, Config: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	result := Result{Kind: "tls", Address: address, Latency: time.Since(start)}
	if err != nil {
		result.Failure = err.Error()
		return result
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.Failure = "unexpected TLS connection type"
		return result
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Failure = "no peer certificate"
		return result
	}
	expiry := state.PeerCertificates[0].NotAfter.UTC()
	result.ExpiresAt = &expiry
	result.OK = true
	return result
}
func PublicAddress(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return true
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}
