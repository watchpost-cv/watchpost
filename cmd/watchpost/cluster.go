package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/watchpost-cv/watchpost/internal/audit"
	"github.com/watchpost-cv/watchpost/internal/cluster"
	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/store"
)

type clusterRuntime struct {
	db          *store.Store
	identity    *cluster.IdentityService
	pairing     *cluster.PairingService
	members     *cluster.MemberService
	transport   *cluster.Transport
	distributed *cluster.DistributedService
}

func openClusterRuntime(dataDir string) (*clusterRuntime, error) {
	cfg, err := config.Load(config.Overrides{DataDir: dataDir})
	if err != nil {
		return nil, err
	}
	db, err := store.Open(context.Background(), cfg.DataDir)
	if err != nil {
		return nil, err
	}
	identity := cluster.NewIdentityService(db)
	members := cluster.NewMemberService(db)
	transport := cluster.NewTransport(db, identity)
	return &clusterRuntime{db: db, identity: identity, pairing: cluster.NewPairingService(db, identity), members: members, transport: transport, distributed: cluster.NewDistributedService(db, identity, members, transport)}, nil
}

func runCluster(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: watchpost cluster <identity|configure|invite|join|joins|collect|approve|reject|members|status|summary|enable|disable|rotate|revoke|remove>")
	}
	command := args[0]
	fs := flag.NewFlagSet("watchpost cluster "+command, flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "Watchpost data directory")
	jsonOut := fs.Bool("json", false, "emit JSON")
	name := fs.String("name", "", "cluster display name")
	endpoint := fs.String("endpoint", "", "public HTTPS endpoint")
	remoteURL := fs.String("url", "", "remote Watchpost HTTPS URL")
	tokenFile := fs.String("token-file", "", "file containing invitation token; use - for stdin")
	secretFile := fs.String("secret-file", "", "write newly generated secret to this file")
	target := fs.String("target", "all", "all, members, or a node ID")
	ca := fs.String("ca", "", "CA certificate (PEM) to trust for the remote HTTPS endpoint")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	pos := fs.Args()
	rt, err := openClusterRuntime(*dataDir)
	if err != nil {
		return err
	}
	defer rt.db.Close()
	ctx := context.Background()
	printValue := func(v any) error {
		enc := json.NewEncoder(os.Stdout)
		if !*jsonOut {
			enc.SetIndent("", "  ")
		}
		return enc.Encode(v)
	}
	systemAudit := audit.Entry{Action: "cluster_cli", ObjectType: "cluster"}
	switch command {
	case "identity":
		if len(pos) != 0 {
			return errors.New("identity accepts no positional arguments")
		}
		v, err := rt.identity.Ensure(ctx, version)
		if err != nil {
			return err
		}
		return printValue(map[string]any{"identity": v, "fingerprint": v.Fingerprint()})
	case "configure", "init":
		if len(pos) != 0 {
			return errors.New("configure accepts no positional arguments")
		}
		v, err := rt.identity.Update(ctx, *name, *endpoint, nil, version)
		if err != nil {
			return err
		}
		return printValue(map[string]any{"identity": v, "fingerprint": v.Fingerprint()})
	case "invite":
		if *secretFile == "" {
			return errors.New("invite requires --secret-file PATH; invitation tokens are never printed in normal output")
		}
		v, err := rt.pairing.Invite(ctx, systemAudit)
		if err != nil {
			return err
		}
		if err = writeSecret(*secretFile, v.Token); err != nil {
			return err
		}
		v.Token = ""
		return printValue(v)
	case "join":
		if *remoteURL == "" || *tokenFile == "" {
			return errors.New("join requires --url HTTPS_URL and --token-file PATH (or - for stdin)")
		}
		token, err := readSecret(*tokenFile)
		if err != nil {
			return err
		}
		client, err := clusterClient(*ca)
		if err != nil {
			return err
		}
		v, err := rt.pairing.BeginOutbound(ctx, *remoteURL, token, client)
		if err != nil {
			return err
		}
		return printValue(v)
	case "joins":
		v, err := rt.pairing.ListOutbound(ctx)
		if err != nil {
			return err
		}
		return printValue(v)
	case "collect":
		if len(pos) != 1 {
			return errors.New("collect requires outbound join ID")
		}
		client, err := clusterClient(*ca)
		if err != nil {
			return err
		}
		v, err := rt.pairing.CollectOutbound(ctx, pos[0], client)
		if err != nil {
			return err
		}
		return printValue(v)
	case "approve", "reject":
		if len(pos) != 1 {
			return fmt.Errorf("%s requires join request ID", command)
		}
		_, err := rt.pairing.Decide(ctx, pos[0], command == "approve", systemAudit)
		return err
	case "members":
		v, err := rt.members.List(ctx)
		if err != nil {
			return err
		}
		return printValue(v)
	case "status":
		if err := cluster.ValidateTarget(*target); err != nil {
			return err
		}
		return printValue(rt.distributed.ClusterStatus(ctx, version, *target))
	case "summary":
		if err := cluster.ValidateTarget(*target); err != nil {
			return err
		}
		return printValue(rt.distributed.ClusterSummary(ctx, version, *target))
	case "enable", "disable":
		if len(pos) != 1 {
			return fmt.Errorf("%s requires node ID", command)
		}
		return rt.members.SetEnabled(ctx, pos[0], command == "enable", systemAudit)
	case "revoke":
		if len(pos) != 1 {
			return errors.New("revoke requires node ID")
		}
		return rt.members.Revoke(ctx, pos[0], systemAudit)
	case "remove":
		if len(pos) != 1 {
			return errors.New("remove requires node ID")
		}
		return rt.members.Remove(ctx, pos[0], systemAudit)
	case "rotate":
		if len(pos) != 1 || *secretFile == "" {
			return errors.New("rotate requires node ID and --secret-file PATH")
		}
		secret, err := rt.members.RotateInbound(ctx, pos[0], systemAudit)
		if err != nil {
			return err
		}
		if err = writeSecret(*secretFile, secret); err != nil {
			return err
		}
		return printValue(map[string]string{"node_id": pos[0], "state": "rotation_pending"})
	default:
		return fmt.Errorf("unknown cluster command %q", command)
	}
}

func readSecret(path string) (string, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 4096))
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(b))
	if value == "" {
		return "", errors.New("secret input is empty")
	}
	return value, nil
}
func writeSecret(path, value string) error {
	if path == "-" {
		return errors.New("refusing to print secret to stdout; use a file path")
	}
	return os.WriteFile(path, []byte(value+"\n"), 0600)
}

// clusterClient returns an HTTP client that trusts the given CA (PEM) for
// remote HTTPS endpoints, or the default client when ca is empty.
func clusterClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return &http.Client{Timeout: 15 * time.Second}, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificates found in CA file")
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}, nil
}
