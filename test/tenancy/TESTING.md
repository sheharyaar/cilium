# Testing tenancy by hand

How to stand up the prototype, confirm the parts that work, and reproduce the
one that does not. Every command here was run against a live kind cluster; the
output shown is real.

`test/tenancy/run.sh` automates the assertions. This document is for looking at
the state directly, which is what you want when something fails.

## Contents

- [Setup](#setup)
- [A shell helper](#a-shell-helper)
- [Confirming the parts that work](#confirming-the-parts-that-work)
- [Probes and pod readiness](#probes-and-pod-readiness)
- [Where a tenant's conntrack lives](#where-a-tenants-conntrack-lives)
- [Fixed: NodePort reply](#fixed-nodeport-reply-was-not-reverse-natted)
- [Reproducing the gateway-route bug](#reproducing-the-gateway-route-bug)
- [Checking the startup guards](#checking-the-startup-guards)
- [Teardown](#teardown)

## Setup

Needs `kind`, `kubectl`, `docker` and the `cilium` CLI on PATH.

```bash
make kind WORKERS=2
make kind-image          # builds localhost:5000/cilium/cilium-dev:local
```

```bash
cilium install \
  --chart-directory=./install/kubernetes/cilium --version= --wait \
  --set=image.override=localhost:5000/cilium/cilium-dev:local \
  --set=image.pullPolicy=Never \
  --set=operator.image.override=localhost:5000/cilium/operator-generic:local \
  --set=operator.image.pullPolicy=Never \
  --set=ipam.mode=multi-pool \
  --set=routingMode=tunnel --set=tunnelProtocol=geneve \
  --set=kubeProxyReplacement=true --set=ipv6.enabled=false \
  --set=enableIPv4Masquerade=false --set=enableIPv6Masquerade=false \
  --set=extraArgs='{--enable-tenancy}'
```

Masquerading is off, and now refused outright by a startup guard.

The earlier reasoning here was that multi-pool IPAM panics with iptables
masquerading unless `egressMasqueradeInterfaces` is set. That is true but
incomplete: `bpf.masquerade=true` turns iptables masquerading off
(`IptablesMasqueradingIPv4Enabled()` is `!EnableBPFMasquerade &&
EnableIPv4Masquerade`), so the panic never fires and the combination does start.
It was tried on this cluster and the agents came up fine.

What it does instead is make NodePort intermittent. With masquerading on, the
same NodePort request alternated between `200` and a timeout, for both tenants,
across consecutive attempts; with it off, three consecutive full runs passed.
The cause has not been isolated. `snat_v4_needs_masquerade()` is also still
tenant-blind in deciding whether a packet came from a local endpoint.

An intermittent data path is worse to live with than a refused one, so
`--enable-ipv4-masquerade` is now rejected at startup. Nothing in this document
needs the default VPC to reach the internet.

Multi-pool IPAM then blocks every untenanted pod until a pool named `default`
exists, so create it once the agents are up:

```bash
kubectl apply -f test/tenancy/manifests/01-default-pool.yaml
```

The order matters and only works this way round. `CiliumPodIPPool` is a CRD that
the operator registers, so applying the pool on a fresh cluster before installing
Cilium fails with `ensure CRDs are installed first`. Installing first is fine:
the agents come up and block untenanted pods until the pool appears, which is
exactly what the next command resolves.

Then the workloads:

```bash
kubectl apply -f test/tenancy/manifests/
```

```bash
kubectl -n acme get pods -o wide
```

These workloads define no probes, so they reach `Ready` normally. That is worth
being precise about, because the neighbouring limitation is easy to overstate:
see [Probes and pod readiness](#probes-and-pod-readiness) below. Give a tenant
pod a `readinessProbe` and it will never become ready.

## A shell helper

Most inspection runs inside an agent. This picks the agent on a given node:

```bash
agent() {  # agent <node> <cilium-dbg args...>
  local node="$1"; shift
  local pod
  pod="$(kubectl -n kube-system get pods -l k8s-app=cilium \
        --field-selector "spec.nodeName=${node}" \
        -o jsonpath='{.items[0].metadata.name}')"
  kubectl -n kube-system exec "${pod}" -c cilium-agent -- cilium-dbg "$@"
}
```

Server pods are pinned to `kind-worker`, clients and the gateway to
`kind-worker2`.

## Confirming the parts that work

### Tenant IDs are allocated

```bash
kubectl get ciliumtenants \
  -o custom-columns=NAME:.metadata.name,ID:.status.tenantID,COND:.status.conditions[0].reason
```

```
NAME     ID    COND
acme     1     Allocated
globex   2     Allocated
```

Restart the operator and check the IDs do not move — they are rebuilt from these
statuses, not from memory:

```bash
kubectl -n kube-system rollout restart deploy/cilium-operator
```

### Both tenants allocated from the same CIDR

```bash
kubectl get pods -A -o wide | grep -E 'acme|globex'
```

Both tenants' pods come out of `10.64.0.0/16`. Whether any two land on the exact
same address is luck; the pools overlapping is the point.

### The ipcache is keyed by tenant

```bash
agent kind-worker bpf ipcache list | head
```

```
10.64.0.42/32@1   identity=105119 ... tunnelendpoint=172.18.0.2 flags=hastunnel
10.64.0.15/32@2   identity=188971 ... tunnelendpoint=172.18.0.2 flags=hastunnel
10.128.0.11/32    identity=4      ...
```

The `@1` and `@2` suffixes are the tenant. Default-VPC entries have no suffix,
which is the "tenant 0 is unchanged" property.

### The endpoint map is keyed by tenant

```bash
agent kind-worker bpf endpoint list | grep '10\.64\.'
```

```
10.64.0.15@2:0   id=2869  sec_id=188971 ... ifindex=13
10.64.0.42@1:0   id=17    sec_id=105119 ... ifindex=15
```

Two endpoints that would collide on address alone, separated by tenant. The `:0`
is the port field of the dump format, not the tenant.

### Identities land in the tenant's numeric range

```bash
agent kind-worker endpoint list | grep -E 'policy.tenant|^[0-9]'
```

Every acme identity has `identity >> 16 == 1`, every globex identity `== 2`:

```bash
python3 -c 'print(105119 >> 16, 188971 >> 16)'   # 1 2
```

The injected label is visible on the endpoint too:

```
k8s:io.cilium.k8s.policy.tenant=acme
```

### Per-tenant conntrack maps exist

```bash
kubectl -n kube-system exec "$(kubectl -n kube-system get pods \
  -l k8s-app=cilium -o jsonpath='{.items[0].metadata.name}')" \
  -c cilium-agent -- ls /sys/fs/bpf/tc/globals/ | grep per_cluster
```

```
cilium_per_cluster_ct_any4
cilium_per_cluster_ct_any4_1
cilium_per_cluster_ct_any4_2
```

The suffixed maps are the inner maps, one per tenant. Delete a tenant and its
inner maps go with it.

### Isolation

```bash
ACME_SRV=$(kubectl -n acme get pod -l app=server -o jsonpath='{.items[0].status.podIP}')
GLOBEX_SRV=$(kubectl -n globex get pod -l app=server -o jsonpath='{.items[0].status.podIP}')

# in-tenant, cross-node: succeeds
kubectl -n acme exec deploy/client -- curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' "http://${ACME_SRV}/"

# cross-tenant: times out
kubectl -n acme exec deploy/client -- curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' "http://${GLOBEX_SRV}/"
```

The second should hang and exit 28. Nothing denies it: the address simply does
not resolve in acme's ipcache slice. To see that directly, run a monitor on the
client's node while the request is in flight:

```bash
agent kind-worker2 monitor --type drop
```

### In-tenant ClusterIP

Use the VIP, not the DNS name. Resolving a name needs kube-dns, which lives in
the default VPC and is unreachable from inside a tenant — per-tenant DNS is a
deployment requirement of this design, not a bug:

```bash
SVC=$(kubectl -n acme get svc server -o jsonpath='{.spec.clusterIP}')
kubectl -n acme exec deploy/client -- curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' "http://${SVC}/"
```

## Probes and pod readiness

Two claims here are easy to run together, and only one of them is true.

**Kubelet cannot reach a tenant pod's IP.** True, and by design. Tenant pods get
no per-endpoint host route, because two tenants may hold the same address and the
routes would collide in the host table. Anything originating in the host network
namespace, kubelet included, has no way to reach them.

**Tenant pods therefore never become Ready.** False. A pod with no
`readinessProbe` is Ready once its containers are running; kubelet asks the
container runtime, not the network. The workloads in `manifests/` define no
probes and reach `Ready` like any other pod.

The limitation bites only when a probe is actually configured. To see it:

```bash
kubectl -n acme patch deploy server --type=json -p='[{
  "op": "add",
  "path": "/spec/template/spec/containers/0/readinessProbe",
  "value": {"httpGet": {"path": "/", "port": 80}, "periodSeconds": 2}
}]'

kubectl -n acme get pods -l app=server -w
```

The new pod stays `0/1 Running` indefinitely. `kubectl describe` shows the probe
failing with a connection timeout to the pod IP, and a Deployment configured this
way never completes its rollout. Revert with:

```bash
kubectl -n acme patch deploy server --type=json -p='[{
  "op": "remove", "path": "/spec/template/spec/containers/0/readinessProbe"
}]'
```

This is the same limitation from a different angle: the host cannot reach tenant
pods, so anything host-originated fails, and probes are the case operators hit
first. It is production-gating rather than cosmetic — user-defined probes on
tenant workloads are routine — and the intended fix is kube-OVN's TPROXY shape,
where the probe terminates at a proxy that re-originates the connection inside
the tenant. That is named as follow-up 1 in the design notes and is not
implemented here.

## Where a tenant's conntrack lives

Two maps are in play and the split is deliberate, so it is worth knowing which
is which before reading any conntrack dump.

Everything belonging to an endpoint — both directions of every flow — is tracked
in that endpoint's tenant map. `select_ct_map4()` in `bpf/bpf_lxc.c` keys on
`TENANT_ID`, the per-endpoint compile-time constant, for `CT_INGRESS` and
`CT_EGRESS` alike. Note it deliberately does *not* read `CB_CLUSTER_ID_INGRESS`
the way the ClusterMesh path does: that meta is set on some paths into an
endpoint and not others, and reading it would scatter one endpoint's flows
across maps depending on how each packet arrived.

The one exception is the NodePort forward entry created by `nodeport_svc_lb4()`,
which stays in the **global** map even when the backend is a tenant's. The
program that has to find it again on the reply is
`nodeport_rev_dnat_fwd_ipv4()` in bpf_host's to-netdev, and bpf_host serves
every endpoint on the node, so it has no single tenant. The only handle on one
would be the backend address the reply carries, which is exactly the value
tenancy makes ambiguous. Put that entry in the tenant's map and it becomes
invisible to the one program that needs it.

The cost is one unresolved collision: two tenants holding the same backend
address share a conntrack entry if an identical client address *and* port
reaches both. That needs two different external clients, behind the same NAT,
picking the same source port, hitting two tenants' NodePorts, at the same time.
Narrow, but real, and not currently detected.

So a healthy dump looks like this — endpoint flows split by tenant, NodePort
forward entries in global:

```bash
agent kind-worker bpf ct list global  | grep NodePort
agent kind-worker bpf ct list cluster 1 | grep 'TCP IN'
agent kind-worker bpf ct list cluster 2 | grep 'TCP IN'
```

```
# global
TCP OUT 172.18.0.5:43192 -> 10.64.0.98:80  Flags=[ NodePort ] RevNAT=7
TCP OUT 172.18.0.5:40804 -> 10.64.0.48:80  Flags=[ NodePort ] RevNAT=10
# cluster 1 (acme)
TCP IN 172.18.0.5:43192 -> 10.64.0.98:80   SourceSecurityID=2
TCP IN 10.64.0.7:43190  -> 10.64.0.98:80   SourceSecurityID=81032
# cluster 2 (globex)
TCP IN 172.18.0.5:40804 -> 10.64.0.48:80   SourceSecurityID=2
TCP IN 10.64.0.13:42726 -> 10.64.0.48:80   SourceSecurityID=166877
```

If you ever see the same connection with an entry in *both* a tenant map and
global, the two halves of the datapath disagree about scope and a reply is about
to go out untranslated. That is what the fixed bug below looked like.

## Fixed: NodePort reply was not reverse-NATted

Kept because the shape of the failure is instructive and the diagnosis method
generalises.

The symptom was that a NodePort request reached the right tenant's backend and
the backend answered, but the reply left as `10.64.0.42:80 -> <client>` instead
of `<node>:31080 -> <client>`, so the client dropped it and the SYN retried
until curl timed out.

Two separate mistakes, both about *which map*:

1. `nodeport_svc_lb4()` wrote the forward entry into the backend's tenant map.
   Nothing on the reply path could reach it, for the reason in the section
   above. Fixed by leaving it global.
2. `ipv4_policy()` in `bpf/bpf_lxc.c` looked its `CT_INGRESS` entry up through
   `select_ct_map4()` but created it with a bare `get_ct_map4()`. Lookup in one
   map, create in another: every packet of the connection came back `CT_NEW`,
   policy was re-evaluated each time, and the reply never matched anything with
   a rev-NAT index. Fixed by creating in the same map the lookup used.

The second one is the more general trap and worth checking for elsewhere: a
lookup and its paired create must agree on the map, and the compiler will not
tell you when they do not.

To verify the fix, dump both maps as above. The decisive question is whether one
connection appears in exactly one place per direction. A NodePort entry in
global with a non-zero `RevNAT`, and its endpoint-side entries in the tenant
map, is correct. The same connection appearing with `RevNAT=0` in global
alongside a tenant-map copy is the bug.

## Reproducing the gateway-route bug

The tenant default route is never installed.

Everything the reconciler needs is present. The gateway pod is running with an
address in the tenant:

```bash
kubectl -n acme get pods -l app=egress-gateway -o wide
```

It has a CiliumEndpoint:

```bash
kubectl -n acme get ciliumendpoints
```

```
egress-gateway-...   93170   ready   10.64.0.10
```

whose labels match the tenant's selector:

```bash
kubectl -n acme get ciliumendpoint -l app=egress-gateway -o jsonpath='{.items[0].metadata.labels}'
kubectl get ciliumtenant acme -o jsonpath='{.spec.egressGateway}'
```

```
{"app":"egress-gateway","pod-template-hash":"..."}
{"namespace":"acme","podSelector":{"matchLabels":{"app":"egress-gateway"}}}
```

And the tenant has an ID. But the route is absent from every agent:

```bash
for n in kind-control-plane kind-worker kind-worker2; do
  echo "--- $n"; agent "$n" bpf ipcache list | grep '0.0.0.0/0'
done
```

Only the default VPC's world entry appears (`0.0.0.0/0  identity=2`), never
`0.0.0.0/0@1`. Nor is there a log line:

```bash
kubectl -n kube-system logs -l k8s-app=cilium --tail=-1 | grep -i 'tenant default route'
```

Consequence, which is what the e2e sees:

```bash
kubectl -n acme exec deploy/client -- curl -sS --max-time 5 -o /dev/null -w '%{http_code}\n' http://1.1.1.1/
```

times out, identically to a tenant with no gateway at all — which is why the
failure is silent.

Where to look: `pkg/tenancy/cell/gateway.go` holds the reconciler and its logic
is unit tested (`gateway_test.go`, nine cases covering matching, ordering,
withdrawal and out-of-order events). The wiring is in `pkg/tenancy/cell/cell.go`,
`watchGatewayEndpoints`, and is not covered by any test. Start by proving the
observer is entered and receiving events at all — a log on the first event, or
whether `p.CiliumEndpoints` is non-nil at registration.

## Checking the startup guards

Tenancy refuses to start alongside features that resolve identities at cluster
ID 0. Each of these should keep the agent from starting, with the reason in the
log:

```bash
# should refuse: IPv6 is not tenant-aware yet
cilium install ... --set=ipv6.enabled=true --set=extraArgs='{--enable-tenancy}'

# should refuse: native routing cannot disambiguate overlapping IPs
cilium install ... --set=routingMode=native --set=extraArgs='{--enable-tenancy}'

# should refuse: only multi-pool IPAM can hand out per-tenant pools
cilium install ... --set=ipam.mode=cluster-pool --set=extraArgs='{--enable-tenancy}'

# should refuse: a DSR conntrack entry cannot be scoped to a tenant
cilium install ... --set=loadBalancer.mode=dsr --set=extraArgs='{--enable-tenancy}'

# should refuse: masquerading makes NodePort intermittent
cilium install ... --set=enableIPv4Masquerade=true --set=extraArgs='{--enable-tenancy}'
```

The DSR guard is the one added last and the reasoning behind it is the same as
the NodePort one above. `nodeport_dsr_ingress_ipv4()` runs in bpf_host, bpf_xdp
and bpf_overlay, none of which serve a single endpoint, so it has to leave its
conntrack entry in the global map. But a DSR reply from a local backend leaves
through bpf_lxc, which *does* know its tenant and looks in the tenant's map. The
two would never meet. `hybrid` is refused too, since it is DSR for TCP.

```bash
kubectl -n kube-system logs -l k8s-app=cilium --tail=-1 | grep 'enable-tenancy'
```

All conflicts are reported at once, so a misconfigured install learns about
every problem in a single restart.

One guard is worth exercising deliberately, because getting it wrong stopped the
agent from starting on a perfectly ordinary cluster: tenancy must **not** refuse
merely because `--clustermesh-config` is set. The Helm chart always passes that
path. A plain install with tenancy enabled has to come up.

## Teardown

```bash
kubectl delete -f test/tenancy/manifests/ --ignore-not-found
make kind-down
```
