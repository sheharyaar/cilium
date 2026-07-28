# Tenancy e2e results

Run on kind (3 nodes: control-plane + 2 workers), Cilium built from this branch,
IPv4 only, geneve tunnel, multi-pool IPAM, kube-proxy replacement, masquerading
disabled, `--enable-tenancy`.

Two tenants, `acme` and `globex`, each owning one namespace, each with a
`CiliumPodIPPool` carrying the **same** CIDR `10.64.0.0/16`.

## Result

| # | Assertion | Result |
|---|---|---|
| 0 | operator allocates distinct tenant IDs | **PASS** (acme=1, globex=2) |
| 1 | overlapping CIDRs coexist | **PASS** |
| 2 | in-tenant cross-node pod to pod | **PASS** (both tenants) |
| 3 | cross-tenant pod to pod blocked | **PASS** |
| 4 | in-tenant ClusterIP | **PASS** (both tenants) |
| 5 | NodePort into a tenant backend | **FAIL** — forward path works, reply is not reverse-NATed |
| 6 | egress via the tenant gateway | **FAIL** — the default route is never installed |

Design criteria 1, 2 and 3 are met on a live cluster. Criterion 5 is partly met:
the hard part works, the reply does not. Criterion 4 is not met.

## What the run confirmed directly

Beyond the assertions, the following were observed on the running cluster and
are the first live evidence for several commits in this series:

Tenant-keyed ipcache, with default-VPC entries unsuffixed alongside them:

```
10.64.0.10/32@1   identity=93170
10.64.0.24/32@1   identity=130080
10.64.0.42/32@1   identity=105119
10.64.0.15/32@2   identity=188971
10.64.0.58/32@2   identity=169580
10.128.0.11/32    identity=4
```

Per-tenant identity ranges. Every acme identity above has high bits 1 and every
globex identity has high bits 2, which is what the datapath reads back as the
tenant.

Tenant-tagged load-balancer backends:

```
6   0.0.0.0:31080/TCP   NodePort   1 => 10.64.0.42@1:80/TCP (active)
9   0.0.0.0:31081/TCP   NodePort   1 => 10.64.0.15@2:80/TCP (active)
```

Per-tenant conntrack maps created from the tenant lifecycle, on every node:

```
Created per-tenant conntrack maps tenantID=1
Created per-tenant conntrack maps tenantID=2
```

## Failure 5: NodePort reply is not reverse-NATed

The forward direction is correct. `cilium-dbg monitor` on the node hosting the
backend shows the request reaching the right tenant's pod and the pod answering:

```
-> endpoint 17  identity world->105119  172.18.0.5:44432 -> 10.64.0.42:80 tcp SYN
-> network      identity 105119->world  10.64.0.42:80 -> 172.18.0.5:44432 tcp SYN, ACK
```

Identity 105119 is acme's server, so the same-address disambiguation this
feature exists for is working: the service selected a backend in tenant 1 and
the packet was delivered to tenant 1's endpoint.

The reply leaves as `10.64.0.42:80 -> 172.18.0.5` rather than being translated
back to `172.18.0.2:31080`, so the client discards it and the SYN is retried
until the connection times out.

The likely cause is the conntrack entry moved by the NodePort commit. The
forward entry is created in the backend's per-tenant map, and the reply from a
local tenant backend leaves through `bpf_lxc`, which selects the per-tenant map
too, so the two were expected to agree. They evidently do not, and the next step
is to compare the tuple and scope each side uses rather than assume the map
choice alone is the difference. Reverting the NodePort conntrack change to the
global map would be the first thing to try, since that isolates it from the
lookup change in the same commit.

## Failure 6: tenant default route is never installed

The gateway pod runs, has a CiliumEndpoint, and its labels match the tenant's
`egressGateway.podSelector`:

```
egress-gateway-...   93170   ready   10.64.0.10
labels: {"app":"egress-gateway","pod-template-hash":"..."}
```

No `0.0.0.0/0@1` entry appears in any agent's ipcache, and no agent logged
"Installed tenant default route". The reconciler's unit tests cover the matching
and ordering logic, so the gap is in the wiring rather than the logic: the
CiliumEndpoint observer is the untested part, and whether it receives events at
all has not been established.

## Two bugs this run found and fixed

**The ClusterMesh guard was a false positive.** It treated a non-empty
`--clustermesh-config` as evidence that ClusterMesh was in use, but the Helm
chart passes that path unconditionally, so the agent refused to start on a plain
cluster. Now keyed on a non-zero cluster ID, which is what actually collides.

**The CiliumTenant CRD was unknown to the watcher.** Listing it in
`agentCRDResourceNames()` makes the agent block on it, and
`GetGroupsForCiliumResources` fatals on any name missing from its mapping. Added
as `skip`, matching `CiliumPodIPPool`, since the tenancy cell consumes it through
`Resource[T]`.

Neither was reachable from unit tests or the BPF suite.

## Reproducing

```
make kind WORKERS=2
make kind-image
kubectl apply -f test/tenancy/manifests/01-default-pool.yaml
cilium install --chart-directory=./install/kubernetes/cilium --version= --wait \
  --set=image.override=localhost:5000/cilium/cilium-dev:local --set=image.pullPolicy=Never \
  --set=operator.image.override=localhost:5000/cilium/operator-generic:local \
  --set=operator.image.pullPolicy=Never \
  --set=ipam.mode=multi-pool --set=routingMode=tunnel --set=tunnelProtocol=geneve \
  --set=kubeProxyReplacement=true --set=ipv6.enabled=false \
  --set=enableIPv4Masquerade=false --set=enableIPv6Masquerade=false \
  --set=extraArgs='{--enable-tenancy}'
./test/tenancy/run.sh
```

Masquerading is off because multi-pool IPAM refuses to start with iptables
masquerading unless `egressMasqueradeInterfaces` is set, and no assertion needs
the default VPC to reach the internet. Note that `snat_v4_needs_masquerade` is
still tenant-blind, so enabling BPF masquerading with tenancy has not been
examined.
