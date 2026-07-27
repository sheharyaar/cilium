// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"fmt"
	"sort"

	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
)

// Resolver maps namespaces to the tenant (VPC) they belong to.
//
// Implementations are safe for concurrent use. Tenant ID 0 is the default VPC:
// it is returned for every namespace when tenancy is disabled, for namespaces
// no tenant selects, and for namespaces whose tenant has no allocated ID yet.
type Resolver interface {
	// TenantIDForNamespace returns the datapath tenant ID of a namespace.
	TenantIDForNamespace(namespace string) uint16

	// TenantNameForNamespace returns the CiliumTenant name owning a namespace,
	// or the empty string for the default VPC. It is used for identity label
	// injection, where the human-readable name rather than the ID is wanted.
	TenantNameForNamespace(namespace string) string

	// TenantIDForName returns the datapath tenant ID of a CiliumTenant by name,
	// or 0 if it is unknown or has no allocated ID. The identity allocator uses
	// this to map the tenant name carried in an identity's labels back to the ID
	// the datapath encodes.
	TenantIDForName(tenantName string) uint16

	// Enabled reports whether multi-tenancy is turned on.
	Enabled() bool
}

type tenantEntry struct {
	name string
	id   uint16
	sel  slim_labels.Selector
}

// NamespaceResolver is the concrete Resolver, fed by the CiliumTenant and
// Namespace observers in the tenancy cell.
//
// Lookups do a linear scan over the tenants. That is intentional: there can be
// at most ClusterIDMax (255) tenants, and a scan avoids having to invalidate a
// derived namespace->tenant index on every tenant or namespace label change.
type NamespaceResolver struct {
	mu      lock.RWMutex
	enabled bool

	tenants    map[string]tenantEntry
	namespaces map[string]slim_labels.Set
}

func NewNamespaceResolver(enabled bool) *NamespaceResolver {
	return &NamespaceResolver{
		enabled:    enabled,
		tenants:    make(map[string]tenantEntry),
		namespaces: make(map[string]slim_labels.Set),
	}
}

func (r *NamespaceResolver) Enabled() bool {
	return r.enabled
}

// UpsertTenant records a tenant and its compiled namespace selector. An ID of 0
// means the operator has not allocated one yet; the tenant is tracked so that a
// later status update is picked up, but it selects nothing until then.
func (r *NamespaceResolver) UpsertTenant(name string, id uint16, sel *slim_metav1.LabelSelector) error {
	// An empty or nil selector matches every namespace, which would drag the
	// entire cluster into a single tenant. Treat it as a configuration error.
	if sel == nil || (len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0) {
		return fmt.Errorf("tenant %q: namespaceSelector must not be empty", name)
	}

	compiled, err := slim_metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return fmt.Errorf("tenant %q: compiling namespaceSelector: %w", name, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenants[name] = tenantEntry{name: name, id: id, sel: compiled}
	return nil
}

func (r *NamespaceResolver) DeleteTenant(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tenants, name)
}

func (r *NamespaceResolver) UpsertNamespace(name string, labels map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.namespaces[name] = slim_labels.Set(labels)
}

func (r *NamespaceResolver) DeleteNamespace(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.namespaces, name)
}

func (r *NamespaceResolver) TenantIDForNamespace(namespace string) uint16 {
	_, id := r.lookup(namespace)
	return id
}

func (r *NamespaceResolver) TenantNameForNamespace(namespace string) string {
	name, _ := r.lookup(namespace)
	return name
}

func (r *NamespaceResolver) TenantIDForName(tenantName string) uint16 {
	if !r.enabled || tenantName == "" {
		return 0
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.tenants[tenantName].id
}

// ConflictingTenants returns the names of the tenants that also select the
// namespace but lost the lowest-ID tie-break. An empty result means no conflict.
func (r *NamespaceResolver) ConflictingTenants(namespace string) []string {
	if !r.enabled {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	matches := r.matchesLocked(namespace)
	if len(matches) < 2 {
		return nil
	}

	names := make([]string, 0, len(matches)-1)
	for _, m := range matches[1:] {
		names = append(names, m.name)
	}
	return names
}

func (r *NamespaceResolver) lookup(namespace string) (string, uint16) {
	if !r.enabled {
		return "", 0
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	matches := r.matchesLocked(namespace)
	if len(matches) == 0 {
		return "", 0
	}
	return matches[0].name, matches[0].id
}

// matchesLocked returns every tenant selecting the namespace, ordered by
// ascending tenant ID so that the winner of an ambiguous namespace is stable
// regardless of map iteration order. Tenants without an allocated ID are
// skipped: they cannot be represented in the datapath yet.
func (r *NamespaceResolver) matchesLocked(namespace string) []tenantEntry {
	nsLabels, ok := r.namespaces[namespace]
	if !ok {
		return nil
	}

	var matches []tenantEntry
	for _, tenant := range r.tenants {
		if tenant.id == 0 {
			continue
		}
		if tenant.sel.Matches(nsLabels) {
			matches = append(matches, tenant)
		}
	}

	sort.Slice(matches, func(i, j int) bool { return matches[i].id < matches[j].id })
	return matches
}
