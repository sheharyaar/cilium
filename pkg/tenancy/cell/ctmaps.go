// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// ctMapManager is the part of ctmap.PerClusterCTMapper the tenant lifecycle
// needs. Narrowing it keeps the reconciler testable without BPF privileges.
type ctMapManager interface {
	CreateClusterCTMaps(clusterID uint32) error
	DeleteClusterCTMaps(clusterID uint32) error
}

// tenantCTMaps keeps the per-tenant conntrack maps in step with the set of
// tenants.
//
// With cluster-aware addressing compiled in, the datapath selects a conntrack
// map per non-zero cluster ID (bpf/lib/conntrack_map.h, get_cluster_ct_map4).
// Tenancy reuses that dimension, so every tenant needs its inner map to exist
// before any of its traffic is tracked. Without one the lookup returns NULL and
// the packet is dropped.
//
// Tenant 0 is the default VPC and keeps using the global conntrack maps.
type tenantCTMaps struct {
	logger *slog.Logger
	maps   ctMapManager

	mu lock.Mutex
	// present tracks the tenants whose inner maps this agent created, so a
	// resync does not recreate them and a delete for an unknown tenant is a
	// no-op.
	present map[uint32]struct{}
}

func newTenantCTMaps(logger *slog.Logger, maps ctMapManager) *tenantCTMaps {
	return &tenantCTMaps{
		logger:  logger,
		maps:    maps,
		present: make(map[uint32]struct{}),
	}
}

// ensure creates the tenant's conntrack maps if they do not exist yet.
func (t *tenantCTMaps) ensure(tenantID uint32) error {
	if t.maps == nil || tenantID == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.present[tenantID]; ok {
		return nil
	}

	if err := t.maps.CreateClusterCTMaps(tenantID); err != nil {
		// Deliberately not recorded as present: a retry must try again, or the
		// tenant's traffic would be conntracked in the global maps.
		return fmt.Errorf("creating conntrack maps for tenant %d: %w", tenantID, err)
	}

	t.present[tenantID] = struct{}{}
	t.logger.Info("Created per-tenant conntrack maps", logfields.TenantID, tenantID)
	return nil
}

// remove deletes the tenant's conntrack maps.
func (t *tenantCTMaps) remove(tenantID uint32) error {
	if t.maps == nil || tenantID == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.present[tenantID]; !ok {
		// A tenant that never had an allocated ID never got maps.
		return nil
	}

	if err := t.maps.DeleteClusterCTMaps(tenantID); err != nil {
		return fmt.Errorf("deleting conntrack maps for tenant %d: %w", tenantID, err)
	}

	delete(t.present, tenantID)
	t.logger.Info("Removed per-tenant conntrack maps", logfields.TenantID, tenantID)
	return nil
}
