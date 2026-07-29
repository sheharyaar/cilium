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
| 5 | NodePort into a tenant backend | **PASS** (both tenants) |
| 6 | egress via the tenant gateway | **FAIL** — the default route is never installed |

Design criteria 1, 2, 3 and 5 are met on a live cluster. Criterion 4 is not
met.

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

## Fixed after the first run: NodePort reply was not reverse-NATed

The first run had criterion 5 failing: the request reached the right tenant's
backend and the backend answered, but the reply left as `10.64.0.42:80 ->
<client>` instead of `<node>:31080`, so the client discarded it.

Two independent scope mistakes, both found by dumping the global and per-tenant
conntrack maps side by side:

**The NodePort forward entry was written to the backend's tenant map.** Nothing
on the reply path can read it there. The program that looks it up again is
`nodeport_rev_dnat_fwd_ipv4()` in bpf_host's to-netdev, which serves every
endpoint on the node and so has no single tenant; the only handle on one would
be the backend address the reply carries, which is exactly the value tenancy
makes ambiguous. That entry now stays in the global map. The residual collision
— two tenants sharing a backend address, reached by an identical client address
and port — is documented in TESTING.md and not detected.

**`ipv4_policy()` looked its CT_INGRESS entry up in one map and created it in
another.** The lookup went through `select_ct_map4()`, the create used a bare
`get_ct_map4()`. Every packet of the connection therefore came back `CT_NEW`,
policy was re-evaluated per packet, and the reply never matched an entry
carrying a rev-NAT index. This one predates tenancy as a latent inconsistency;
scoping `select_ct_map4()` is what made it bite.

`select_ct_map4()` now keys on the endpoint's own `TENANT_ID` for both
directions rather than on `CB_CLUSTER_ID_INGRESS`, so an endpoint's flows land
in one map regardless of how the packet arrived. Verified on the cluster:

```
# global
TCP OUT 172.18.0.5:43192 -> 10.64.0.98:80  [ NodePort ] RevNAT=7
TCP OUT 172.18.0.5:40804 -> 10.64.0.48:80  [ NodePort ] RevNAT=10
# cluster 1 (acme)          # cluster 2 (globex)
TCP IN 10.64.0.7:43190  -> 10.64.0.98:80   TCP IN 10.64.0.13:42726 -> 10.64.0.48:80
```

A DSR load-balancer mode hits the same wall at
`nodeport_dsr_ingress_ipv4()` and cannot be resolved the same way, so
`--bpf-lb-mode=dsr` and `hybrid` are now refused at startup.

## Found while testing: an agent restart breaks tenancy for running pods

Not an assertion failure, because `run.sh` recreates pods, which is exactly what
hid it.

Restart the agents with `kubectl rollout restart ds/cilium` and leave the pods
alone, and the endpoints come back with identities in the **tenant 0** range:

```
Identity of endpoint changed ... k8sPodName=acme/server-...
    old-identity=67846 new-identity=56077
```

`67846 >> 16 == 1`, which is acme. `56077 >> 16 == 0`, which is the default VPC.
The first label resolution after restart is missing
`k8s:io.cilium.k8s.policy.tenant=acme` entirely; a later one has it, but the
identity does not move back.

The visible consequence is that load-balancer backends lose their tenant tag --
`10.64.0.98:80/TCP` where it should read `10.64.0.98@1:80/TCP` -- so the NodePort
endpoint lookup resolves in the wrong tenant and the service stops working until
the pods are recreated.

This looks like an ordering problem between endpoint restoration and the tenancy
resolver learning its namespace mapping, but that has not been confirmed.

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
cilium install --chart-directory=./install/kubernetes/cilium --version= --wait \
  --set=image.override=localhost:5000/cilium/cilium-dev:local --set=image.pullPolicy=Never \
  --set=operator.image.override=localhost:5000/cilium/operator-generic:local \
  --set=operator.image.pullPolicy=Never \
  --set=ipam.mode=multi-pool --set=routingMode=tunnel --set=tunnelProtocol=geneve \
  --set=kubeProxyReplacement=true --set=ipv6.enabled=false \
  --set=enableIPv4Masquerade=false --set=enableIPv6Masquerade=false \
  --set=extraArgs='{--enable-tenancy}'
kubectl apply -f test/tenancy/manifests/01-default-pool.yaml
./test/tenancy/run.sh
```

The `default` pool goes on after the install, not before: `CiliumPodIPPool` is a
CRD the operator registers, so applying it to a fresh cluster fails with `ensure
CRDs are installed first`. The agents block untenanted pods until it appears,
which is harmless.

Masquerading is off and now refused by a startup guard. The reason given
earlier -- that multi-pool IPAM will not start with iptables masquerading -- is
true but sidesteppable with `bpf.masquerade=true`, which was tried here: the
agents start fine, and the per-tenant NAT maps are created. What it breaks is
NodePort, which becomes intermittent (the same request alternating between `200`
and a timeout for both tenants, where it is reliable with masquerading off). The
cause is not isolated, so the configuration is rejected rather than shipped
flaky. See TESTING.md.
