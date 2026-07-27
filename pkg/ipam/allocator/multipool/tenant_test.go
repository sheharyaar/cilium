// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPoolOverlapAcrossTenantsIsAllowed(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t))

	// The point of tenancy: two tenants may carve pods out of the same CIDR.
	require.NoError(t, p.UpsertPool("acme-pool",
		[]string{"10.10.0.0/16"}, 27, nil, 0, WithTenant("acme")))
	require.NoError(t, p.UpsertPool("globex-pool",
		[]string{"10.10.0.0/16"}, 27, nil, 0, WithTenant("globex")))
}

func TestPoolOverlapWithinTenantIsRejected(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t))
	require.NoError(t, p.UpsertPool("acme-pool",
		[]string{"10.10.0.0/16"}, 27, nil, 0, WithTenant("acme")))

	// A narrower CIDR inside the tenant's existing range is still an overlap.
	err := p.UpsertPool("acme-pool-2",
		[]string{"10.10.1.0/24"}, 27, nil, 0, WithTenant("acme"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "10.10.1.0/24")
	assert.ErrorContains(t, err, "acme-pool")
	assert.ErrorContains(t, err, `tenant "acme"`)

	// The rejected pool must not have been recorded.
	_, exists := p.pools["acme-pool-2"]
	assert.False(t, exists)

	// A wider CIDR containing the tenant's existing range is rejected too.
	err = p.UpsertPool("acme-pool-3",
		[]string{"10.0.0.0/8"}, 27, nil, 0, WithTenant("acme"))
	require.Error(t, err)
}

func TestPoolOverlapUntenantedUnchanged(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t))

	// Two pools with no tenant label keep today's behaviour, which is to accept
	// the overlap. Rejecting it here would break existing deployments that do
	// not use tenancy at all.
	require.NoError(t, p.UpsertPool("plain-a", []string{"10.20.0.0/16"}, 24, nil, 0))
	require.NoError(t, p.UpsertPool("plain-b", []string{"10.20.0.0/16"}, 24, nil, 0))
}

func TestPoolOverlapTenantVersusDefaultVPC(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t))
	require.NoError(t, p.UpsertPool("plain", []string{"10.30.0.0/16"}, 24, nil, 0))

	// A tenant pool may reuse a default-VPC CIDR: they are different routing
	// domains, which is exactly what the cluster_id dimension buys.
	require.NoError(t, p.UpsertPool("acme-pool",
		[]string{"10.30.0.0/16"}, 27, nil, 0, WithTenant("acme")))

	// And the reverse ordering behaves the same.
	require.NoError(t, p.UpsertPool("plain-2", []string{"10.40.0.0/16"}, 24, nil, 0))
	require.NoError(t, p.UpsertPool("acme-pool-2",
		[]string{"10.40.0.0/16"}, 27, nil, 0, WithTenant("acme")))
}

func TestPoolOverlapWithinTenantIPv6(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t))
	require.NoError(t, p.UpsertPool("acme-pool",
		nil, 0, []string{"fd00:10::/80"}, 96, WithTenant("acme")))

	require.Error(t, p.UpsertPool("acme-pool-2",
		nil, 0, []string{"fd00:10::/88"}, 96, WithTenant("acme")))

	// Different family cannot overlap, so a v4 CIDR is fine.
	require.NoError(t, p.UpsertPool("acme-pool-v4",
		[]string{"10.50.0.0/16"}, 27, nil, 0, WithTenant("acme")))

	// Same v6 CIDR in another tenant is fine.
	require.NoError(t, p.UpsertPool("globex-pool",
		nil, 0, []string{"fd00:10::/80"}, 96, WithTenant("globex")))
}

func TestPoolOverlapReupsertOfSamePoolAllowed(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t))
	require.NoError(t, p.UpsertPool("acme-pool",
		[]string{"10.10.0.0/16"}, 27, nil, 0, WithTenant("acme")))

	// A pool must not conflict with itself when its spec is re-reconciled, and
	// growing it with a second disjoint CIDR must work.
	require.NoError(t, p.UpsertPool("acme-pool",
		[]string{"10.10.0.0/16"}, 27, nil, 0, WithTenant("acme")))
	require.NoError(t, p.UpsertPool("acme-pool",
		[]string{"10.10.0.0/16", "10.11.0.0/16"}, 27, nil, 0, WithTenant("acme")))
}

func TestPoolOverlapWithinOwnCIDRsRejected(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t))

	// A single tenant pool listing two overlapping CIDRs is self-inconsistent.
	err := p.UpsertPool("acme-pool",
		[]string{"10.10.0.0/16", "10.10.1.0/24"}, 27, nil, 0, WithTenant("acme"))
	require.Error(t, err)
	assert.ErrorContains(t, err, "acme-pool")
}

func TestPoolOverlapTenantChangeOnExistingPool(t *testing.T) {
	p := NewPoolAllocator(hivetest.Logger(t))
	require.NoError(t, p.UpsertPool("shared-cidr-a",
		[]string{"10.60.0.0/16"}, 27, nil, 0, WithTenant("acme")))
	require.NoError(t, p.UpsertPool("shared-cidr-b",
		[]string{"10.60.0.0/16"}, 27, nil, 0, WithTenant("globex")))

	// Relabelling b into acme now collides with a, and must be refused rather
	// than silently producing two pools handing out the same addresses inside
	// one routing domain.
	require.Error(t, p.UpsertPool("shared-cidr-b",
		[]string{"10.60.0.0/16"}, 27, nil, 0, WithTenant("acme")))

	// The stored pool keeps its previous tenant.
	assert.Equal(t, "globex", p.pools["shared-cidr-b"].tenant)
}
