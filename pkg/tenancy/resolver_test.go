// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func selector(t *testing.T, labels map[string]string) *slim_metav1.LabelSelector {
	t.Helper()
	return &slim_metav1.LabelSelector{MatchLabels: labels}
}

const tenantLabel = "tenant.cilium.io/name"

func TestResolverDisabled(t *testing.T) {
	r := NewNamespaceResolver(false)
	require.False(t, r.Enabled())

	// Even fully populated, a disabled resolver reports the default VPC so the
	// tenant-0 code path stays untouched when --enable-tenancy is unset.
	require.NoError(t, r.UpsertTenant("acme", 3, selector(t, map[string]string{tenantLabel: "acme"})))
	r.UpsertNamespace("ns-a", map[string]string{tenantLabel: "acme"})
	require.Equal(t, uint16(0), r.TenantIDForNamespace("ns-a"))
	require.Equal(t, "", r.TenantNameForNamespace("ns-a"))
}

func TestResolverSelectedNamespace(t *testing.T) {
	r := NewNamespaceResolver(true)
	require.NoError(t, r.UpsertTenant("acme", 3, selector(t, map[string]string{tenantLabel: "acme"})))
	r.UpsertNamespace("ns-a", map[string]string{tenantLabel: "acme"})
	r.UpsertNamespace("ns-b", map[string]string{})

	require.Equal(t, uint16(3), r.TenantIDForNamespace("ns-a"))
	require.Equal(t, "acme", r.TenantNameForNamespace("ns-a"))

	require.Equal(t, uint16(0), r.TenantIDForNamespace("ns-b"))
	require.Equal(t, "", r.TenantNameForNamespace("ns-b"))

	// Unknown namespaces are in the default VPC.
	require.Equal(t, uint16(0), r.TenantIDForNamespace("nope"))
}

func TestResolverTenantWithoutAllocatedID(t *testing.T) {
	r := NewNamespaceResolver(true)
	// status.tenantID == 0 means the operator has not allocated yet: the
	// namespace must stay in the default VPC rather than land in tenant 0's
	// datapath under a tenant name.
	require.NoError(t, r.UpsertTenant("acme", 0, selector(t, map[string]string{tenantLabel: "acme"})))
	r.UpsertNamespace("ns-a", map[string]string{tenantLabel: "acme"})

	require.Equal(t, uint16(0), r.TenantIDForNamespace("ns-a"))
	require.Equal(t, "", r.TenantNameForNamespace("ns-a"))
}

func TestResolverTenantIDForName(t *testing.T) {
	r := NewNamespaceResolver(true)
	require.NoError(t, r.UpsertTenant("acme", 3, selector(t, map[string]string{tenantLabel: "acme"})))

	// This is the lookup the identity allocator uses to turn the tenant name in
	// an identity's labels back into the ID the datapath encodes.
	require.Equal(t, uint16(3), r.TenantIDForName("acme"))

	// Unknown tenants and the empty name are the default VPC, never a guess.
	require.Equal(t, uint16(0), r.TenantIDForName("globex"))
	require.Equal(t, uint16(0), r.TenantIDForName(""))

	r.DeleteTenant("acme")
	require.Equal(t, uint16(0), r.TenantIDForName("acme"))
}

func TestResolverTenantIDForNameDisabled(t *testing.T) {
	r := NewNamespaceResolver(false)
	require.NoError(t, r.UpsertTenant("acme", 3, selector(t, map[string]string{tenantLabel: "acme"})))
	require.Equal(t, uint16(0), r.TenantIDForName("acme"))
}

func TestResolverDeleteTenant(t *testing.T) {
	r := NewNamespaceResolver(true)
	require.NoError(t, r.UpsertTenant("acme", 3, selector(t, map[string]string{tenantLabel: "acme"})))
	r.UpsertNamespace("ns-a", map[string]string{tenantLabel: "acme"})
	require.Equal(t, uint16(3), r.TenantIDForNamespace("ns-a"))

	r.DeleteTenant("acme")
	require.Equal(t, uint16(0), r.TenantIDForNamespace("ns-a"))
}

func TestResolverDeleteNamespace(t *testing.T) {
	r := NewNamespaceResolver(true)
	require.NoError(t, r.UpsertTenant("acme", 3, selector(t, map[string]string{tenantLabel: "acme"})))
	r.UpsertNamespace("ns-a", map[string]string{tenantLabel: "acme"})
	require.Equal(t, uint16(3), r.TenantIDForNamespace("ns-a"))

	r.DeleteNamespace("ns-a")
	require.Equal(t, uint16(0), r.TenantIDForNamespace("ns-a"))
}

func TestResolverNamespaceRelabelled(t *testing.T) {
	r := NewNamespaceResolver(true)
	require.NoError(t, r.UpsertTenant("acme", 3, selector(t, map[string]string{tenantLabel: "acme"})))
	require.NoError(t, r.UpsertTenant("globex", 4, selector(t, map[string]string{tenantLabel: "globex"})))

	r.UpsertNamespace("ns-a", map[string]string{tenantLabel: "acme"})
	require.Equal(t, uint16(3), r.TenantIDForNamespace("ns-a"))

	r.UpsertNamespace("ns-a", map[string]string{tenantLabel: "globex"})
	require.Equal(t, uint16(4), r.TenantIDForNamespace("ns-a"))
}

func TestResolverAmbiguousNamespaceLowestIDWins(t *testing.T) {
	r := NewNamespaceResolver(true)
	// Both tenants select ns-a. The resolution must be deterministic and
	// independent of insertion order: the lowest tenant ID wins.
	require.NoError(t, r.UpsertTenant("globex", 9, selector(t, map[string]string{"shared": "yes"})))
	require.NoError(t, r.UpsertTenant("acme", 4, selector(t, map[string]string{"shared": "yes"})))
	r.UpsertNamespace("ns-a", map[string]string{"shared": "yes"})

	require.Equal(t, uint16(4), r.TenantIDForNamespace("ns-a"))
	require.Equal(t, "acme", r.TenantNameForNamespace("ns-a"))

	// Conflicts are reported so the operator can surface them.
	conflicts := r.ConflictingTenants("ns-a")
	require.ElementsMatch(t, []string{"globex"}, conflicts)
}

func TestResolverEmptySelectorSelectsNothing(t *testing.T) {
	r := NewNamespaceResolver(true)
	// An empty selector matches every namespace in Kubernetes semantics, which
	// would silently place the whole cluster into one tenant. Reject it.
	require.Error(t, r.UpsertTenant("acme", 3, &slim_metav1.LabelSelector{}))
	require.Error(t, r.UpsertTenant("acme", 3, nil))

	r.UpsertNamespace("ns-a", map[string]string{})
	require.Equal(t, uint16(0), r.TenantIDForNamespace("ns-a"))
}

func TestResolverMatchExpressions(t *testing.T) {
	r := NewNamespaceResolver(true)
	sel := &slim_metav1.LabelSelector{
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
			Key:      tenantLabel,
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"acme", "acme-staging"},
		}},
	}
	require.NoError(t, r.UpsertTenant("acme", 3, sel))

	r.UpsertNamespace("ns-a", map[string]string{tenantLabel: "acme-staging"})
	r.UpsertNamespace("ns-b", map[string]string{tenantLabel: "other"})

	require.Equal(t, uint16(3), r.TenantIDForNamespace("ns-a"))
	require.Equal(t, uint16(0), r.TenantIDForNamespace("ns-b"))
}
