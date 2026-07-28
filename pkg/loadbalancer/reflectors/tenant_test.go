// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"iter"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
)

func tenantTestBackends(addr string) iter.Seq2[cmtypes.AddrCluster, *k8s.Backend] {
	ac := cmtypes.MustParseAddrCluster(addr)
	be := &k8s.Backend{
		Ports: map[loadbalancer.L4Addr][]string{
			{Protocol: loadbalancer.TCP, Port: 80}: {"http"},
		},
		Conditions: k8s.BackendConditionReady,
	}
	return func(yield func(cmtypes.AddrCluster, *k8s.Backend) bool) {
		yield(ac, be)
	}
}

func convertOne(t *testing.T, svcNamespace string, tenantID uint16, addr string) loadbalancer.Backend {
	t.Helper()

	cfg := loadbalancer.ExternalConfig{EnableIPv4: true, EnableIPv6: true}
	name := loadbalancer.NewServiceName(svcNamespace, "svc")

	var got []loadbalancer.Backend
	for be := range convertEndpoints(hivetest.Logger(t), cfg, name, tenantID,
		tenantTestBackends(addr)) {
		got = append(got, be)
	}
	require.Len(t, got, 1)
	return got[0]
}

func TestConvertEndpointsTagsTenantBackend(t *testing.T) {
	be := convertOne(t, "acme-ns", 3, "10.10.0.5")

	// The tenant rides in the backend address, which is what
	// NewBackend4ValueV3 turns into lb4_backend.cluster_id, and from there
	// drives the NodePort endpoint lookup and conntrack map selection.
	assert.Equal(t, uint32(3), be.Address.AddrCluster().ClusterID())
	assert.Equal(t, "10.10.0.5", be.Address.AddrCluster().Addr().String())
}

func TestConvertEndpointsUntenantedBackendUnchanged(t *testing.T) {
	be := convertOne(t, "plain-ns", 0, "10.0.0.5")

	assert.Equal(t, uint32(0), be.Address.AddrCluster().ClusterID())
	assert.Equal(t, "10.0.0.5", be.Address.AddrCluster().Addr().String())
}

// The tenant must go in the address, not in Backend.ClusterID. That field is
// statedb ownership: a non-zero value marks the backend as belonging to a
// remote cluster, and SetBackendsOfCluster would then treat these local
// backends as somebody else's and orphan them.
func TestConvertEndpointsDoesNotClaimRemoteOwnership(t *testing.T) {
	be := convertOne(t, "acme-ns", 3, "10.10.0.5")

	assert.Equal(t, uint32(writer.LocalClusterID), be.ClusterID,
		"a tenant backend is still owned by the local cluster")
}

func TestConvertEndpointsSameAddressDistinctPerTenant(t *testing.T) {
	// The point of the feature: one address, two tenants, two distinct
	// backends as far as the datapath is concerned.
	acme := convertOne(t, "acme-ns", 3, "10.10.0.5")
	globex := convertOne(t, "globex-ns", 4, "10.10.0.5")

	assert.NotEqual(t, acme.Address.AddrCluster(), globex.Address.AddrCluster())
	assert.Equal(t, acme.Address.AddrCluster().Addr(), globex.Address.AddrCluster().Addr())
}

func TestConvertEndpointsIPv6Tenant(t *testing.T) {
	be := convertOne(t, "acme-ns", 3, "fd00:10::5")

	assert.Equal(t, uint32(3), be.Address.AddrCluster().ClusterID())
}
