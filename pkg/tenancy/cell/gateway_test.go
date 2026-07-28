// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ipcache"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/source"
)

// fakeIPCache records the default-route upserts and deletes the reconciler makes.
type fakeIPCache struct {
	upserts []gatewayUpsert
	deletes []string
	err     error
}

type gatewayUpsert struct {
	key      string
	hostIP   string
	identity uint32
}

func (f *fakeIPCache) Upsert(key string, hostIP net.IP, _ uint8, _ *ipcache.K8sMetadata,
	id ipcache.Identity) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	f.upserts = append(f.upserts, gatewayUpsert{
		key:      key,
		hostIP:   hostIP.String(),
		identity: id.ID.Uint32(),
	})
	return false, nil
}

func (f *fakeIPCache) Delete(key string, _ source.Source) bool {
	f.deletes = append(f.deletes, key)
	return false
}

func (f *fakeIPCache) last() gatewayUpsert {
	return f.upserts[len(f.upserts)-1]
}

func selector(t *testing.T, labels map[string]string) slim_labels.Selector {
	t.Helper()
	sel, err := slim_metav1.LabelSelectorAsSelector(&slim_metav1.LabelSelector{MatchLabels: labels})
	require.NoError(t, err)
	return sel
}

func newTestGateways(t *testing.T) (*tenantGateways, *fakeIPCache) {
	t.Helper()
	ipc := &fakeIPCache{}
	return newTenantGateways(hivetest.Logger(t), ipc), ipc
}

func gwCandidate(ns, name string, labels map[string]string) gatewayCandidate {
	return gatewayCandidate{
		namespace: ns,
		name:      name,
		labels:    labels,
		podIP:     "10.10.9.9",
		nodeIP:    "192.168.1.5",
		identity:  0x30123,
	}
}

func TestGatewayInstallsDefaultRoute(t *testing.T) {
	r, ipc := newTestGateways(t)

	require.NoError(t, r.upsertTenant("acme", 3, &gatewaySpec{
		namespace: "acme-gw",
		selector:  selector(t, map[string]string{"app": "gw"}),
	}))
	require.NoError(t, r.upsertEndpoint(gwCandidate("acme-gw", "gw-0", map[string]string{"app": "gw"})))

	require.Len(t, ipc.upserts, 1)
	got := ipc.last()

	// The default route is scoped to the tenant, so LPM only serves it to that
	// tenant's endpoints.
	assert.Equal(t, "0.0.0.0/0@3", got.key)
	// Traffic is tunnelled to the node the gateway pod runs on.
	assert.Equal(t, "192.168.1.5", got.hostIP)
	// And carries the gateway's identity, so policy sees the gateway rather
	// than the real destination.
	assert.Equal(t, uint32(0x30123), got.identity)
}

func TestGatewayIgnoresNonMatchingPod(t *testing.T) {
	r, ipc := newTestGateways(t)

	require.NoError(t, r.upsertTenant("acme", 3, &gatewaySpec{
		namespace: "acme-gw",
		selector:  selector(t, map[string]string{"app": "gw"}),
	}))

	// Right namespace, wrong labels.
	require.NoError(t, r.upsertEndpoint(gwCandidate("acme-gw", "other", map[string]string{"app": "web"})))
	// Right labels, wrong namespace: a pod elsewhere must not become the
	// gateway just by being labelled like one.
	require.NoError(t, r.upsertEndpoint(gwCandidate("other-ns", "gw-0", map[string]string{"app": "gw"})))

	assert.Empty(t, ipc.upserts)
}

func TestGatewayTenantWithoutSpec(t *testing.T) {
	r, ipc := newTestGateways(t)

	require.NoError(t, r.upsertTenant("acme", 3, nil))
	require.NoError(t, r.upsertEndpoint(gwCandidate("acme-gw", "gw-0", map[string]string{"app": "gw"})))

	assert.Empty(t, ipc.upserts, "a tenant with no egressGateway gets no default route")
}

func TestGatewayTenantWithoutAllocatedID(t *testing.T) {
	r, ipc := newTestGateways(t)

	// Tenant ID 0 means the operator has not allocated yet. Installing
	// 0.0.0.0/0@0 would hijack the default VPC's default route.
	require.NoError(t, r.upsertTenant("acme", 0, &gatewaySpec{
		namespace: "acme-gw",
		selector:  selector(t, map[string]string{"app": "gw"}),
	}))
	require.NoError(t, r.upsertEndpoint(gwCandidate("acme-gw", "gw-0", map[string]string{"app": "gw"})))

	assert.Empty(t, ipc.upserts)
}

func TestGatewayPodDeleted(t *testing.T) {
	r, ipc := newTestGateways(t)

	require.NoError(t, r.upsertTenant("acme", 3, &gatewaySpec{
		namespace: "acme-gw",
		selector:  selector(t, map[string]string{"app": "gw"}),
	}))
	require.NoError(t, r.upsertEndpoint(gwCandidate("acme-gw", "gw-0", map[string]string{"app": "gw"})))
	require.Len(t, ipc.upserts, 1)

	require.NoError(t, r.deleteEndpoint("acme-gw", "gw-0"))

	// The route is withdrawn rather than left pointing at a pod that is gone,
	// which would blackhole the tenant's egress.
	assert.Equal(t, []string{"0.0.0.0/0@3"}, ipc.deletes)
}

func TestGatewayPodMoved(t *testing.T) {
	r, ipc := newTestGateways(t)

	require.NoError(t, r.upsertTenant("acme", 3, &gatewaySpec{
		namespace: "acme-gw",
		selector:  selector(t, map[string]string{"app": "gw"}),
	}))

	gw := gwCandidate("acme-gw", "gw-0", map[string]string{"app": "gw"})
	require.NoError(t, r.upsertEndpoint(gw))

	// Rescheduled onto another node with a new address.
	gw.podIP = "10.10.9.10"
	gw.nodeIP = "192.168.1.6"
	gw.identity = 0x30124
	require.NoError(t, r.upsertEndpoint(gw))

	require.Len(t, ipc.upserts, 2)
	assert.Equal(t, "192.168.1.6", ipc.last().hostIP)
	assert.Equal(t, uint32(0x30124), ipc.last().identity)
}

func TestGatewayTenantDeleted(t *testing.T) {
	r, ipc := newTestGateways(t)

	require.NoError(t, r.upsertTenant("acme", 3, &gatewaySpec{
		namespace: "acme-gw",
		selector:  selector(t, map[string]string{"app": "gw"}),
	}))
	require.NoError(t, r.upsertEndpoint(gwCandidate("acme-gw", "gw-0", map[string]string{"app": "gw"})))

	r.deleteTenant("acme")
	assert.Equal(t, []string{"0.0.0.0/0@3"}, ipc.deletes)
}

func TestGatewaySpecRemoved(t *testing.T) {
	r, ipc := newTestGateways(t)

	require.NoError(t, r.upsertTenant("acme", 3, &gatewaySpec{
		namespace: "acme-gw",
		selector:  selector(t, map[string]string{"app": "gw"}),
	}))
	require.NoError(t, r.upsertEndpoint(gwCandidate("acme-gw", "gw-0", map[string]string{"app": "gw"})))
	require.Len(t, ipc.upserts, 1)

	// Dropping spec.egressGateway must withdraw the route.
	require.NoError(t, r.upsertTenant("acme", 3, nil))
	assert.Equal(t, []string{"0.0.0.0/0@3"}, ipc.deletes)
}

func TestGatewayEndpointArrivesBeforeTenant(t *testing.T) {
	r, ipc := newTestGateways(t)

	// Event ordering is not guaranteed: the CiliumEndpoint may be observed
	// before the CiliumTenant that selects it.
	require.NoError(t, r.upsertEndpoint(gwCandidate("acme-gw", "gw-0", map[string]string{"app": "gw"})))
	assert.Empty(t, ipc.upserts)

	require.NoError(t, r.upsertTenant("acme", 3, &gatewaySpec{
		namespace: "acme-gw",
		selector:  selector(t, map[string]string{"app": "gw"}),
	}))

	require.Len(t, ipc.upserts, 1)
	assert.Equal(t, "0.0.0.0/0@3", ipc.last().key)
}
