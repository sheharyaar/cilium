// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupPrivilegedMap(t *testing.T) *lxcMap {
	t.Helper()
	testutils.PrivilegedTest(t)
	bpf.CheckOrMountFS(hivetest.Logger(t), "")

	m := &lxcMap{
		bpfMap: bpf.NewMap(
			"test_cilium_lxc",
			ebpf.Hash,
			&EndpointKey{},
			&EndpointInfo{},
			MaxEntries,
			0,
		),
	}
	require.NoError(t, m.bpfMap.OpenOrCreate())
	t.Cleanup(func() {
		_ = m.bpfMap.Unpin()
		_ = m.bpfMap.Close()
	})
	return m
}

// TestPrivilegedSameIPAcrossTenants is the property success criterion 1 rests
// on: two endpoints with the same pod IP in different tenants coexist in the
// endpoint map, and deleting one leaves the other intact.
func TestPrivilegedSameIPAcrossTenants(t *testing.T) {
	m := setupPrivilegedMap(t)

	addr := netip.MustParseAddr("10.10.0.5")
	ep1 := fakeFrontend{ipv4: addr, tenantID: 1}
	ep2 := fakeFrontend{ipv4: addr, tenantID: 2}

	require.NoError(t, m.WriteEndpoint(ep1))
	require.NoError(t, m.WriteEndpoint(ep2))

	dump, err := m.DumpToMap()
	require.NoError(t, err)
	require.Len(t, dump, 2, "the same IP in two tenants must be two entries")
	assert.Contains(t, dump, EndpointAddr{Addr: addr, TenantID: 1})
	assert.Contains(t, dump, EndpointAddr{Addr: addr, TenantID: 2})

	// Deleting tenant 1's endpoint must not disturb tenant 2's.
	require.Empty(t, m.DeleteElement(hivetest.Logger(t), ep1))

	dump, err = m.DumpToMap()
	require.NoError(t, err)
	require.Len(t, dump, 1)
	assert.Contains(t, dump, EndpointAddr{Addr: addr, TenantID: 2})
	assert.NotContains(t, dump, EndpointAddr{Addr: addr, TenantID: 1})
}

// TestPrivilegedTenantEntryIsNotReachableAsDefaultVPC guards against the
// asymmetry that would silently leak entries: a delete issued without the tenant
// must not match a tenant's entry.
func TestPrivilegedTenantEntryIsNotReachableAsDefaultVPC(t *testing.T) {
	m := setupPrivilegedMap(t)

	addr := netip.MustParseAddr("10.10.0.5")
	require.NoError(t, m.WriteEndpoint(fakeFrontend{ipv4: addr, tenantID: 3}))

	// A default-VPC delete of the same address must not find the tenant entry.
	assert.Error(t, m.DeleteEntry(NewEndpointAddr(addr)))

	dump, err := m.DumpToMap()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	// Scoped to the tenant, the delete succeeds.
	require.NoError(t, m.DeleteEntry(EndpointAddr{Addr: addr, TenantID: 3}))

	dump, err = m.DumpToMap()
	require.NoError(t, err)
	require.Empty(t, dump)
}

// TestPrivilegedUntenantedEndpointUnchanged pins the tenant-0 path: an endpoint
// with no tenant produces exactly the entry it did before tenancy existed.
func TestPrivilegedUntenantedEndpointUnchanged(t *testing.T) {
	m := setupPrivilegedMap(t)

	v4 := netip.MustParseAddr("10.0.0.5")
	v6 := netip.MustParseAddr("fd00::5")
	require.NoError(t, m.WriteEndpoint(fakeFrontend{ipv4: v4, ipv6: v6}))

	dump, err := m.DumpToMap()
	require.NoError(t, err)
	require.Len(t, dump, 2)
	assert.Contains(t, dump, NewEndpointAddr(v4))
	assert.Contains(t, dump, NewEndpointAddr(v6))

	require.NoError(t, m.DeleteEntry(NewEndpointAddr(v4)))
	require.NoError(t, m.DeleteEntry(NewEndpointAddr(v6)))

	dump, err = m.DumpToMap()
	require.NoError(t, err)
	require.Empty(t, dump)
}
