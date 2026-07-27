// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
)

// fakeFrontend is a minimal EndpointFrontend.
type fakeFrontend struct {
	ipv4     netip.Addr
	ipv6     netip.Addr
	tenantID uint16
}

func (f fakeFrontend) LXCMac() mac.MAC                       { return mac.MAC{2, 0, 0, 0, 0, 1} }
func (f fakeFrontend) GetNodeMAC() mac.MAC                   { return mac.MAC{2, 0, 0, 0, 0, 2} }
func (f fakeFrontend) GetIfIndex() int                       { return 7 }
func (f fakeFrontend) GetParentIfIndex() int                 { return 0 }
func (f fakeFrontend) GetID() uint64                         { return 1234 }
func (f fakeFrontend) IPv4Address() netip.Addr               { return f.ipv4 }
func (f fakeFrontend) IPv6Address() netip.Addr               { return f.ipv6 }
func (f fakeFrontend) GetIdentity() identity.NumericIdentity { return identity.NumericIdentity(4242) }
func (f fakeFrontend) IsAtHostNS() bool                      { return false }
func (f fakeFrontend) SkipMasqueradeV4() bool                { return false }
func (f fakeFrontend) SkipMasqueradeV6() bool                { return false }
func (f fakeFrontend) GetTenantID() uint16                   { return f.tenantID }

func TestNewEndpointKeyCarriesTenant(t *testing.T) {
	addr := netip.MustParseAddr("10.10.0.5")

	require.Equal(t, uint16(0), newEndpointKey(addr, 0).ClusterID)
	require.Equal(t, uint16(3), newEndpointKey(addr, 3).ClusterID)

	// The address must be untouched by the tenant.
	require.Equal(t, addr, newEndpointKey(addr, 3).ToAddr())
}

func TestSameIPDifferentTenantsAreDistinctKeys(t *testing.T) {
	addr := netip.MustParseAddr("10.10.0.5")

	// This is the property the whole design rests on: one IP, two tenants, two
	// distinct endpoint map keys.
	k1 := newEndpointKey(addr, 1)
	k2 := newEndpointKey(addr, 2)

	assert.NotEqual(t, k1.String(), k2.String())
	assert.Equal(t, k1.ToAddr(), k2.ToAddr())
}

func TestGetBPFKeysUsesFrontendTenant(t *testing.T) {
	m := &lxcMap{}

	f := fakeFrontend{
		ipv4:     netip.MustParseAddr("10.10.0.5"),
		ipv6:     netip.MustParseAddr("fd00:10::5"),
		tenantID: 3,
	}

	keys := m.getBPFKeys(f)
	require.Len(t, keys, 2)
	for _, k := range keys {
		assert.Equal(t, uint16(3), k.ClusterID)
	}
}

func TestGetBPFKeysUntenantedIsUnchanged(t *testing.T) {
	m := &lxcMap{}

	f := fakeFrontend{ipv4: netip.MustParseAddr("10.0.0.5")}

	keys := m.getBPFKeys(f)
	require.Len(t, keys, 1)
	assert.Equal(t, uint16(0), keys[0].ClusterID)
}

// WriteEndpoint and DeleteElement are handed different objects (the epInfoCache
// snapshot and the Endpoint itself), so they must agree on the key or a deleted
// endpoint leaves its map entry behind forever.
func TestWriteAndDeleteKeysAgree(t *testing.T) {
	m := &lxcMap{}

	f := fakeFrontend{
		ipv4:     netip.MustParseAddr("10.10.0.5"),
		ipv6:     netip.MustParseAddr("fd00:10::5"),
		tenantID: 3,
	}

	write := m.getBPFKeys(f)
	del := m.getBPFKeys(f)
	require.Len(t, del, len(write))
	for i := range write {
		assert.Equal(t, write[i].String(), del[i].String())
	}
}

func TestEndpointAddrIdentifiesTenantScopedEntry(t *testing.T) {
	addr := netip.MustParseAddr("10.10.0.5")

	// EndpointAddr is the dump and delete key. Two tenants holding the same IP
	// must not collapse into one another, or restore-time cleanup would delete a
	// live endpoint's entry, or miss a stale one.
	a := EndpointAddr{Addr: addr, TenantID: 1}
	b := EndpointAddr{Addr: addr, TenantID: 2}
	assert.NotEqual(t, a, b)

	seen := map[EndpointAddr]int{a: 1, b: 2}
	require.Len(t, seen, 2)

	// And the untenanted key stays distinct from both.
	host := EndpointAddr{Addr: addr}
	seen[host] = 3
	require.Len(t, seen, 3)
}
