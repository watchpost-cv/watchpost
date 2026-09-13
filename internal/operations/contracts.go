// Package operations declares Watchpost's canonical functional operation surface.
package operations
import("github.com/gantry-tools/gantry-core/contracttest";"github.com/gantry-tools/gantry-core/operation")
var Contracts=[]operation.Contract{
	contract("watchpost.status.read",operation.Read,"GET","/api/v1/status","status","get",operation.Session,""),
	contract("watchpost.actions.create",operation.Mutation,"POST","/api/v1/actions","actions","create",operation.Session,"watchpost.actions.created"),
	contract("watchpost.agent-connections.revoke",operation.Destructive,"POST","/api/v1/agent-connections/{id}/revoke","agent-connections","revoke",operation.Session,"watchpost.agent-connections.revoked"),
}
func contract(id string,kind operation.Kind,method,path,resource,verb string,boundary operation.Boundary,event string) operation.Contract{audit:=operation.Audit{};if kind!=operation.Read{audit=operation.Audit{Required:true,Event:event}};return operation.Contract{SchemaVersion:operation.SchemaVersion,ID:id,Kind:kind,Route:operation.Route{Method:method,Path:path},CLI:&operation.CLI{Resource:resource,Verb:verb},Authorization:operation.Authorization{Boundary:boundary},Audit:audit,Idempotency:operation.Idempotency{RetrySafe:kind==operation.Read},Automation:operation.Automatable}}
func AdoptionManifest()contracttest.Manifest{routes:=make([]operation.Route,len(Contracts));ids:=make([]string,len(Contracts));for i,c:=range Contracts{routes[i],ids[i]=c.Route,c.ID};return contracttest.Manifest{SchemaVersion:1,Project:"watchpost",Operations:Contracts,ObservedRoutes:routes,WebsiteOperations:ids}}
