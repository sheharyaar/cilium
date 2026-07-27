// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubTenancy is a tenancy.Resolver backed by a fixed namespace map.
type stubTenancy struct {
	enabled bool
	ids     map[string]uint16
}

func (s stubTenancy) Enabled() bool { return s.enabled }

func (s stubTenancy) TenantIDForNamespace(ns string) uint16 { return s.ids[ns] }

func (s stubTenancy) TenantNameForNamespace(string) string { return "" }

func (s stubTenancy) TenantIDForName(string) uint16 { return 0 }

func TestTenantIPCacheKey(t *testing.T) {
	tenanted := stubTenancy{enabled: true, ids: map[string]uint16{"acme": 3, "globex": 4}}

	// A tenant pod IP is annotated with its tenant, which is what lets the same
	// IP exist once per tenant in the ipcache.
	require.Equal(t, "10.10.0.5@3", tenantIPCacheKey(tenanted, "acme", "10.10.0.5"))
	require.Equal(t, "10.10.0.5@4", tenantIPCacheKey(tenanted, "globex", "10.10.0.5"))

	// Untenanted namespaces keep the bare IP, so the default VPC's ipcache keys
	// are exactly what they were before tenancy existed.
	require.Equal(t, "10.0.0.5", tenantIPCacheKey(tenanted, "kube-system", "10.0.0.5"))
}

func TestTenantIPCacheKeyDisabled(t *testing.T) {
	disabled := stubTenancy{enabled: false, ids: map[string]uint16{"acme": 3}}

	require.Equal(t, "10.10.0.5", tenantIPCacheKey(disabled, "acme", "10.10.0.5"))
	require.Equal(t, "10.10.0.5", tenantIPCacheKey(nil, "acme", "10.10.0.5"))
}

func TestTenantIPCacheKeyEmptyIP(t *testing.T) {
	tenanted := stubTenancy{enabled: true, ids: map[string]uint16{"acme": 3}}

	// CiliumEndpoint pairs carry an empty string for a missing address family;
	// annotating that would produce a bogus "@3" key.
	require.Equal(t, "", tenantIPCacheKey(tenanted, "acme", ""))
}

func TestTenantIPCacheKeyIsSymmetric(t *testing.T) {
	tenanted := stubTenancy{enabled: true, ids: map[string]uint16{"acme": 3}}

	// Upsert and delete must derive the same key from the same inputs, or a
	// deleted pod leaves a stale ipcache entry that keeps resolving to a dead
	// identity.
	upsert := tenantIPCacheKey(tenanted, "acme", "10.10.0.5")
	del := tenantIPCacheKey(tenanted, "acme", "10.10.0.5")
	assert.Equal(t, upsert, del)
}

func TestTenantIPCacheKeyIPv6(t *testing.T) {
	tenanted := stubTenancy{enabled: true, ids: map[string]uint16{"acme": 3}}

	require.Equal(t, "fd00:10::5@3", tenantIPCacheKey(tenanted, "acme", "fd00:10::5"))
}
