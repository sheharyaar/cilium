// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

func tenantLabels(tenant string) labels.Labels {
	lbls := labels.Labels{
		"app": labels.NewLabel("app", "web", labels.LabelSourceK8s),
	}
	if tenant != "" {
		lbls[k8sConst.PolicyLabelTenant] = labels.NewLabel(
			k8sConst.PolicyLabelTenant, tenant, labels.LabelSourceK8s)
	}
	return lbls
}

func TestTenantIDForLabels(t *testing.T) {
	m := &CachingIdentityAllocator{
		tenantIDs: func(name string) uint32 {
			if name == "acme" {
				return 3
			}
			return 0
		},
	}

	require.Equal(t, uint32(3), m.tenantIDForLabels(tenantLabels("acme")))

	// A tenant the resolver does not know maps to the default VPC rather than
	// to a guessed ID.
	require.Equal(t, uint32(0), m.tenantIDForLabels(tenantLabels("unknown")))

	// No tenant label at all is the default VPC.
	require.Equal(t, uint32(0), m.tenantIDForLabels(tenantLabels("")))
}

func TestTenantIDForLabelsWithoutLookup(t *testing.T) {
	// With tenancy disabled no lookup is registered, so even a label that
	// somehow carries a tenant resolves to the default VPC and the identity
	// allocation path is byte-identical to today.
	m := &CachingIdentityAllocator{}
	require.Equal(t, uint32(0), m.tenantIDForLabels(tenantLabels("acme")))
}

func TestAllocatorForTenantWithTenancyDisabled(t *testing.T) {
	// With tenancy off a non-zero ID is a ClusterMesh cluster ID, not a tenant.
	// Those identities live in the shared allocator's remote caches, so no
	// tenant allocator may be created for them. Getting this wrong would break
	// ClusterMesh identity lookups for clusters that never enabled tenancy.
	m := &CachingIdentityAllocator{}

	for _, id := range []uint32{0, 1, 7, 255} {
		a, err := m.allocatorForTenant(id)
		require.NoError(t, err)
		assert.Equal(t, m.IdentityAllocator, a)
	}
	assert.Empty(t, m.tenantAllocators)
}

func TestAllocatorForTenantBeforeInit(t *testing.T) {
	// With tenancy on but the global allocator not yet initialized there is no
	// backend factory, so this must fail loudly rather than panic.
	m := &CachingIdentityAllocator{
		tenantIDs: func(string) uint32 { return 3 },
	}

	a, err := m.allocatorForTenant(3)
	require.Error(t, err)
	assert.Nil(t, a)
}

func TestTenantIdentityRange(t *testing.T) {
	// The datapath recovers the tenant from the identity's high bits, so every
	// ID the tenant allocator can hand out must report that tenant.
	for _, tenantID := range []uint32{1, 3, 42, 255} {
		minID, maxID, mask := tenantIdentityRange(tenantID)

		require.Equal(t, tenantID, identity.NumericIdentity(minID).ClusterID(),
			"lowest ID of tenant %d must report tenant %d", tenantID, tenantID)
		require.Equal(t, tenantID, identity.NumericIdentity(maxID).ClusterID(),
			"highest ID of tenant %d must report tenant %d", tenantID, tenantID)

		assert.Less(t, minID, maxID)

		// The prefix mask is what the allocator ORs into every selected ID.
		require.Equal(t, tenantID, identity.NumericIdentity(mask).ClusterID())

		// Ranges of adjacent tenants must not touch.
		if tenantID < 255 {
			nextMin, _, _ := tenantIdentityRange(tenantID + 1)
			assert.Less(t, maxID, nextMin)
		}
	}
}

func TestTenantIdentityRangeDiffersFromClusterLocal(t *testing.T) {
	localMin := identity.GetMinimalAllocationIdentity(0)
	localMax := identity.GetMaximumAllocationIdentity(0)

	minID, _, _ := tenantIdentityRange(3)
	assert.Greater(t, identity.NumericIdentity(minID), localMax,
		"tenant range must not overlap the cluster-local range")
	assert.Greater(t, identity.NumericIdentity(minID), localMin)
	require.Equal(t, uint32(0), localMax.ClusterID(),
		"cluster-local identities must keep reporting tenant 0")
}
