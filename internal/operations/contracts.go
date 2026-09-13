// Package operations declares Watchpost's canonical functional operation surface.
package operations

import (
	"github.com/gantry-tools/gantry-core/contracttest"
	"github.com/gantry-tools/gantry-core/operation"
)

type spec struct {
	id, method, path, resource, verb, test string
	kind                                   operation.Kind
	boundary                               operation.Boundary
	capability                             string
	automation                             operation.Automation
	website, cli                           bool
	secrets                                []string
}

var specs = []spec{
	{"watchpost.bootstrap.get", "GET", "/api/v1/bootstrap", "auth", "bootstrap", "internal/server/api_test.go", operation.Read, operation.Public, "", operation.Automatable, true, true, nil},
	{"watchpost.setup.setup", "POST", "/api/v1/setup", "auth", "setup", "internal/server/api_test.go", operation.Mutation, operation.Public, "", operation.Automatable, true, true, []string{"/password"}},
	{"watchpost.login.login", "POST", "/api/v1/login", "auth", "login", "internal/server/api_test.go", operation.Mutation, operation.Public, "", operation.Automatable, true, true, []string{"/password"}},
	{"watchpost.logout.logout", "POST", "/api/v1/logout", "auth", "logout", "internal/server/api_test.go", operation.Destructive, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.posts.create", "POST", "/api/v1/posts", "posts", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.posts.list", "GET", "/api/v1/posts", "posts", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.collectors.list", "GET", "/api/v1/collectors", "collectors", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.posts.get", "GET", "/api/v1/posts/{id}", "posts", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.posts.update", "PUT", "/api/v1/posts/{id}", "posts", "update", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.posts.delete", "DELETE", "/api/v1/posts/{id}", "posts", "delete", "internal/server/api_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.posts.dependencies.create", "POST", "/api/v1/posts/{id}/dependencies", "posts-dependencies", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.posts.collectors.create", "POST", "/api/v1/posts/{id}/collectors", "posts-collectors", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.posts.pairing-tokens.create", "POST", "/api/v1/posts/{id}/pairing-tokens", "posts-pairing-tokens", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.collector.pair", "POST", "/api/collector/v1/pair", "collector", "pair", "internal/server/api_test.go", operation.Mutation, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.agent.pairing-requests.create", "POST", "/api/agent/v2/pairing-requests", "agent-pairing-requests", "create", "internal/server/api_test.go", operation.Mutation, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.agent.rotate", "POST", "/api/agent/v2/rotate", "agent", "rotate", "internal/server/api_test.go", operation.Mutation, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.agent.unpair", "POST", "/api/agent/v2/unpair", "agent", "unpair", "internal/server/api_test.go", operation.Destructive, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.agent.pairing-requests.get", "GET", "/api/agent/v2/pairing-requests/{id}", "agent-pairing-requests", "get", "internal/server/api_test.go", operation.Read, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.agent-pairing-requests.list", "GET", "/api/v1/agent-pairing-requests", "agent-pairing-requests", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.agent-connections.list", "GET", "/api/v1/agent-connections", "agent-connections", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.posts.agent-connections.get", "GET", "/api/v1/posts/{id}/agent-connections", "posts-agent-connections", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.agent-connections.revoke", "POST", "/api/v1/agent-connections/{id}/revoke", "agent-connections", "revoke", "internal/server/api_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.agent-pairing-requests.approve", "POST", "/api/v1/agent-pairing-requests/{id}/approve", "agent-pairing-requests", "approve", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.agent-pairing-requests.reject", "POST", "/api/v1/agent-pairing-requests/{id}/reject", "agent-pairing-requests", "reject", "internal/server/api_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.observations.create", "POST", "/api/v1/observations", "observations", "create", "internal/server/api_test.go", operation.Mutation, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.collector.observations.create", "POST", "/api/collector/v1/observations", "collector-observations", "create", "internal/server/api_test.go", operation.Mutation, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.host-snapshot.get", "GET", "/api/v1/host-snapshot", "host-snapshot", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.checks.create", "POST", "/api/v1/checks", "checks", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.check-schedules.create", "POST", "/api/v1/check-schedules", "check-schedules", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.check-schedules.list", "GET", "/api/v1/check-schedules", "check-schedules", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.posts.history.get", "GET", "/api/v1/posts/{id}/history", "posts-history", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.survey.get", "GET", "/api/v1/survey", "survey", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.rules.create", "POST", "/api/v1/rules", "rules", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.rules.list", "GET", "/api/v1/rules", "rules", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.rules.set-enabled", "POST", "/api/v1/rules/{id}/enabled", "rules", "set-enabled", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.alerts.list", "GET", "/api/v1/alerts", "alerts", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.alerts.acknowledge", "POST", "/api/v1/alerts/{id}/acknowledge", "alerts", "acknowledge", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.notification-routes.create", "POST", "/api/v1/notification-routes", "notification-routes", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.notification-routes.list", "GET", "/api/v1/notification-routes", "notification-routes", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.incidents.create", "POST", "/api/v1/incidents", "incidents", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.incidents.list", "GET", "/api/v1/incidents", "incidents", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.incidents.get", "GET", "/api/v1/incidents/{id}", "incidents", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.incidents.transition", "POST", "/api/v1/incidents/{id}/transition", "incidents", "transition", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.incidents.notes", "POST", "/api/v1/incidents/{id}/notes", "incidents", "notes", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.incidents.assign", "POST", "/api/v1/incidents/{id}/assign", "incidents", "assign", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.logs.create", "POST", "/api/v1/logs", "logs", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.posts.logs.get", "GET", "/api/v1/posts/{id}/logs", "posts-logs", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.changes.create", "POST", "/api/v1/changes", "changes", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.evidence.get", "GET", "/api/v1/evidence/{kind}/{id}", "evidence", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.conversations.create", "POST", "/api/v1/conversations", "conversations", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.conversations.investigate", "POST", "/api/v1/conversations/{id}/investigate", "conversations", "investigate", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.actions.create", "POST", "/api/v1/actions", "actions", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.actions.list", "GET", "/api/v1/actions", "actions", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.actions.approve", "POST", "/api/v1/actions/{id}/approve", "actions", "approve", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.actions.execute", "POST", "/api/v1/actions/{id}/execute", "actions", "execute", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.peers.create", "POST", "/api/v1/peers", "peers", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.peers.list", "GET", "/api/v1/peers", "peers", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.peers.revoke", "POST", "/api/v1/peers/{id}/revoke", "peers", "revoke", "internal/server/api_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.federation.create", "POST", "/api/v1/federation/{peer}", "federation", "create", "internal/server/api_test.go", operation.Mutation, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.devices.snmp.poll", "POST", "/api/v1/devices/snmp/poll", "devices-snmp", "poll", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.device-profiles.create", "POST", "/api/v1/device-profiles", "device-profiles", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.device-profiles.list", "GET", "/api/v1/device-profiles", "device-profiles", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.device-profiles.delete", "DELETE", "/api/v1/device-profiles/{id}", "device-profiles", "delete", "internal/server/api_test.go", operation.Destructive, operation.Capability, "watchpost.role.operator", operation.Automatable, true, true, nil},
	{"watchpost.device-adapters.list", "GET", "/api/v1/device-adapters", "device-adapters", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.device-presets.list", "GET", "/api/v1/device-presets", "device-presets", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.audit.get", "GET", "/api/v1/audit", "audit", "get", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.users.list", "GET", "/api/v1/users", "users", "list", "internal/server/api_test.go", operation.Read, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.users.create", "POST", "/api/v1/users", "users", "create", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.users.role.update", "PUT", "/api/v1/users/{id}/role", "users-role", "update", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.users.reset-password", "POST", "/api/v1/users/{id}/reset-password", "users", "reset-password", "internal/server/api_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, []string{"/password"}},
	{"watchpost.users.revoke-sessions", "POST", "/api/v1/users/{id}/revoke-sessions", "users", "revoke-sessions", "internal/server/api_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.me.password", "POST", "/api/v1/me/password", "me", "password", "internal/server/api_test.go", operation.Mutation, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, []string{"/password"}},
	{"watchpost.cluster.identity.get", "GET", "/api/v1/cluster/identity", "cluster-identity", "get", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.cluster.identity.update", "PUT", "/api/v1/cluster/identity", "cluster-identity", "update", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.invitations.create", "POST", "/api/v1/cluster/invitations", "cluster-invitations", "create", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.join.create", "POST", "/api/cluster/v1/join", "cluster-join", "create", "internal/cluster/cluster_test.go", operation.Mutation, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.cluster.join.get", "GET", "/api/cluster/v1/join/{id}", "cluster-join", "get", "internal/cluster/cluster_test.go", operation.Read, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.cluster.joins.list", "GET", "/api/v1/cluster/joins", "cluster-joins", "list", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.outbound-joins.create", "POST", "/api/v1/cluster/outbound-joins", "cluster-outbound-joins", "create", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.outbound-joins.list", "GET", "/api/v1/cluster/outbound-joins", "cluster-outbound-joins", "list", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.outbound-joins.collect", "POST", "/api/v1/cluster/outbound-joins/{id}/collect", "cluster-outbound-joins", "collect", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.joins.approve", "POST", "/api/v1/cluster/joins/{id}/approve", "cluster-joins", "approve", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.joins.reject", "POST", "/api/v1/cluster/joins/{id}/reject", "cluster-joins", "reject", "internal/cluster/cluster_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.members.list", "GET", "/api/v1/cluster/members", "cluster-members", "list", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.cluster.members.enable", "POST", "/api/v1/cluster/members/{id}/enable", "cluster-members", "enable", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.members.disable", "POST", "/api/v1/cluster/members/{id}/disable", "cluster-members", "disable", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.members.revoke", "POST", "/api/v1/cluster/members/{id}/revoke", "cluster-members", "revoke", "internal/cluster/cluster_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.members.delete", "DELETE", "/api/v1/cluster/members/{id}", "cluster-members", "delete", "internal/cluster/cluster_test.go", operation.Destructive, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.members.rotate", "POST", "/api/v1/cluster/members/{id}/rotate", "cluster-members", "rotate", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.members.outbound-credential.update", "PUT", "/api/v1/cluster/members/{id}/outbound-credential", "cluster-members-outbound-credential", "update", "internal/cluster/cluster_test.go", operation.Mutation, operation.Capability, "watchpost.role.admin", operation.Automatable, true, true, nil},
	{"watchpost.cluster.status.get", "GET", "/api/v1/cluster/status", "cluster-status", "get", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.cluster.summary.get", "GET", "/api/v1/cluster/summary", "cluster-summary", "get", "internal/cluster/cluster_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.cluster.rpc.status.get", "GET", "/api/cluster/v1/rpc/status", "cluster-rpc-status", "get", "internal/cluster/cluster_test.go", operation.Read, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.cluster.rpc.summary.get", "GET", "/api/cluster/v1/rpc/summary", "cluster-rpc-summary", "get", "internal/cluster/cluster_test.go", operation.Read, operation.Service, "", operation.ServiceProtocol, false, false, nil},
	{"watchpost.healthz.get", "GET", "/healthz", "healthz", "get", "internal/server/server_test.go", operation.Read, operation.Public, "", operation.Automatable, false, true, nil},
	{"watchpost.readyz.get", "GET", "/readyz", "readyz", "get", "internal/server/server_test.go", operation.Read, operation.Public, "", operation.Automatable, false, true, nil},
	{"watchpost.version.get", "GET", "/api/v1/version", "version", "get", "internal/server/server_test.go", operation.Read, operation.Public, "", operation.Automatable, false, true, nil},
	{"watchpost.launcher.instances.list", "GET", "/api/launcher/instances", "launcher-instances", "list", "internal/server/server_test.go", operation.Read, operation.Public, "", operation.Automatable, true, true, nil},
	{"watchpost.launcher.config.update", "PUT", "/api/launcher/config", "launcher-config", "update", "internal/server/server_test.go", operation.Mutation, operation.Capability, "launcher.configure.all", operation.Automatable, true, true, nil},
	{"watchpost.diagnostics.get", "GET", "/api/v1/diagnostics", "diagnostics", "get", "internal/server/server_test.go", operation.Read, operation.Public, "", operation.Automatable, false, true, nil},
	{"watchpost.storage.get", "GET", "/api/v1/storage", "storage", "get", "internal/server/server_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
	{"watchpost.backup-status.get", "GET", "/api/v1/backup-status", "backup-status", "get", "internal/server/server_test.go", operation.Read, operation.Capability, "watchpost.role.viewer", operation.Automatable, true, true, nil},
}

var Contracts = buildContracts()

func buildContracts() []operation.Contract {
	out := make([]operation.Contract, 0, len(specs))
	for _, x := range specs {
		var cli *operation.CLI
		if x.cli {
			cli = &operation.CLI{Resource: x.resource, Verb: x.verb, Implemented: true}
		}
		auth := operation.Authorization{Boundary: x.boundary}
		if x.boundary == operation.Capability {
			auth.Capability = x.capability
		}
		audit := operation.Audit{}
		if x.kind != operation.Read {
			audit = operation.Audit{Required: true, Event: x.id + ".performed"}
		}
		schemas := operation.Schemas{Output: x.id + ".response.v1"}
		if x.kind != operation.Read {
			schemas.Input = x.id + ".request.v1"
		}
		out = append(out, operation.Contract{SchemaVersion: operation.SchemaVersion, ID: x.id, Kind: x.kind, Route: operation.Route{Method: x.method, Path: x.path}, CLI: cli, Authorization: auth, Schemas: schemas, Audit: audit, Idempotency: operation.Idempotency{RetrySafe: x.kind == operation.Read}, Automation: x.automation, SecretInputs: append([]string(nil), x.secrets...)})
	}
	return out
}
func Manifest() contracttest.Manifest {
	routes := make([]operation.Route, 0, len(Contracts))
	commands := make([]operation.CLI, 0, len(Contracts))
	ids := []string{}
	evidence := map[string]contracttest.Evidence{}
	for i, c := range Contracts {
		routes = append(routes, c.Route)
		if c.CLI != nil && c.CLI.Implemented {
			commands = append(commands, *c.CLI)
		}
		if specs[i].website {
			ids = append(ids, c.ID)
		}
		evidence[c.ID] = contracttest.Evidence{Website: specs[i].website, Tests: []string{specs[i].test}}
	}
	return contracttest.Manifest{SchemaVersion: 1, Project: "watchpost", Operations: Contracts, ObservedRoutes: routes, ObservedCommands: commands, WebsiteOperations: ids, Evidence: evidence}
}
func AdoptionManifest() contracttest.Manifest { return Manifest() }
