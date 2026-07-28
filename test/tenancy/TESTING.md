# Testing tenancy by hand

How to stand up the prototype, confirm the parts that work, and reproduce the
two that do not. Every command here was run against a live kind cluster; the
output shown is real.

`test/tenancy/run.sh` automates the assertions. This document is for looking at
the state directly, which is what you want when something fails.

## Contents

- [Setup](#setup)
- [A shell helper](#a-shell-helper)
- [Confirming the parts that work](#confirming-the-parts-that-work)
- [Reproducing bug 1: NodePort reply](#reproducing-bug-1-nodeport-reply-is-not-reverse-natted)
- [Reproducing bug 2: gateway route](#reproducing-bug-2-tenant-default-route-is-never-installed)
- [Checking the startup guards](#checking-the-startup-guards)
- [Teardown](#teardown)

## Setup

Needs `kind`, `kubectl`, `docker` and the `cilium` CLI on PATH.

```bash
make kind WORKERS=2
make kind-image          # builds localhost:5000/cilium/cilium-dev:local
```

Multi-pool IPAM blocks every untenanted pod until a pool named `default` exists,
so apply that before installing:

```bash
kubectl apply -f test/tenancy/manifests/01-default-pool.yaml
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

Masquerading is off deliberately. Multi-pool IPAM panics at startup with
iptables masquerading unless `egressMasqueradeInterfaces` is set, and
`snat_v4_needs_masquerade()` is still tenant-blind, so BPF masquerading with
tenancy has not been examined. Nothing in this document needs the default VPC to
reach the internet.

Then the workloads:

```bash
kubectl apply -f test/tenancy/manifests/
```

Do not wait for pods to become `Ready`. Tenant pods have no host-netns route, so
kubelet cannot probe them and they never report ready. Wait for an IP instead:

```bash
kubectl -n acme get pods -o wide
```

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

## Reproducing bug 1: NodePort reply is not reverse-NATted

The service and its tenant-tagged backend are installed correctly:

```bash
agent kind-worker service list | grep -E '31080|31081'
```

```
6   0.0.0.0:31080/TCP   NodePort   1 => 10.64.0.42@1:80/TCP (active)
9   0.0.0.0:31081/TCP   NodePort   1 => 10.64.0.15@2:80/TCP (active)
```

The `@1` and `@2` on the backends are the tenant the load-balancer will scope
its endpoint lookup and conntrack to.

Now drive a request from outside the cluster. The kind network is `kind-cilium`,
not `kind`:

```bash
NODE=$(kubectl get node kind-worker \
  -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' \
  | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1)

docker run --rm --network kind-cilium curlimages/curl:8.10.1 \
  -sS --max-time 5 -o /dev/null -w '%{http_code}\n' "http://${NODE}:31080/"
```

This times out. To see why, run the monitor on the backend's node in one shell:

```bash
agent kind-worker monitor
```

and repeat the curl in another. The interesting two lines:

```
-> endpoint 17  identity world->105119  172.18.0.5:44432 -> 10.64.0.42:80 tcp SYN
-> network      identity 105119->world  10.64.0.42:80 -> 172.18.0.5:44432 tcp SYN, ACK
```

Read them carefully, because they say something better than "it is broken":

- The request **was** delivered to endpoint 17, identity 105119, which is
  acme's server. The service picked a tenant-1 backend and the packet reached
  the tenant-1 endpoint rather than the identically addressed tenant-2 one. The
  disambiguation this whole feature exists for is working.
- The reply leaves as `10.64.0.42:80 -> 172.18.0.5`. It should have been
  translated back to `<node>:31080`. The client sees a SYN,ACK from an address
  it never contacted and drops it, so the SYN is retried until curl gives up.

To confirm the suspect, look at whether the forward entry landed in the tenant's
conntrack map rather than the global one:

```bash
agent kind-worker bpf ct list global | grep 31080
```

Bisecting: `bpf/lib/nodeport.h` changes two things behind `ENABLE_TENANCY`, the
endpoint lookup and the conntrack map. Revert only the conntrack map selection
back to `get_ct_map4(tuple)`, rebuild, and re-run. If revNAT recovers, the map
choice is the cause and the endpoint lookup is fine. Keep both halves separate
while testing; changing them together is how this got missed.

## Reproducing bug 2: tenant default route is never installed

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
```

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
