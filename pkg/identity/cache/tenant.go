// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/kvstore/allocator/doublewrite"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// newIdentityBackend builds an identity allocation backend of the type the
// agent is configured for.
//
// It is shared between the global allocator and the per-tenant allocators, which
// must use the same backend type. Each allocator needs its own instance: a
// backend carries mutable per-allocator store state and cannot be shared.
func newIdentityBackend(
	logger *slog.Logger,
	identitiesPath string,
	owner IdentityAllocatorOwner,
	client versioned.Interface,
	kvstoreClient kvstore.Client,
) (allocator.Backend, error) {
	switch option.Config.IdentityAllocationMode {
	case option.IdentityAllocationModeKVstore:
		logger.Debug("Identity allocation backed by KVStore")
		return kvstoreallocator.NewKVStoreBackend(
			logger,
			kvstoreallocator.KVStoreBackendConfiguration{
				BasePath: identitiesPath,
				Suffix:   owner.GetNodeSuffix(),
				Typ:      &key.GlobalIdentity{},
				Backend:  kvstoreClient,
			})

	case option.IdentityAllocationModeCRD:
		logger.Debug("Identity allocation backed by CRD")
		return identitybackend.NewCRDBackend(logger, identitybackend.CRDBackendConfiguration{
			Store:    nil,
			StoreSet: &atomic.Bool{},
			Client:   client,
			KeyFunc:  (&key.GlobalIdentity{}).PutKeyFromMap,
		})

	case option.IdentityAllocationModeDoubleWriteReadKVstore, option.IdentityAllocationModeDoubleWriteReadCRD:
		readFromKVStore := option.Config.IdentityAllocationMode != option.IdentityAllocationModeDoubleWriteReadCRD
		logger.Debug("Double-Write Identity allocation mode (CRD and KVStore) with reads from KVStore",
			logfields.ReadFromKVStore, readFromKVStore)
		return doublewrite.NewDoubleWriteBackend(
			logger,
			doublewrite.DoubleWriteBackendConfiguration{
				CRDBackendConfiguration: identitybackend.CRDBackendConfiguration{
					Store:    nil,
					StoreSet: &atomic.Bool{},
					Client:   client,
					KeyFunc:  (&key.GlobalIdentity{}).PutKeyFromMap,
				},
				KVStoreBackendConfiguration: kvstoreallocator.KVStoreBackendConfiguration{
					BasePath: identitiesPath,
					Suffix:   owner.GetNodeSuffix(),
					Typ:      &key.GlobalIdentity{},
					Backend:  kvstoreClient,
				},
				ReadFromKVStore: readFromKVStore,
			})

	default:
		return nil, fmt.Errorf("unsupported identity allocation mode %s", option.Config.IdentityAllocationMode)
	}
}

// TenantIDLookup resolves a CiliumTenant name to its datapath tenant ID. It
// returns 0 for an unknown tenant or for the default VPC.
//
// The identity allocator only ever sees the tenant *name*, because that is what
// travels in the identity's label set; this function is how it learns the ID
// that the datapath actually encodes.
type TenantIDLookup func(tenantName string) uint32

// SetTenantIDLookup registers the tenant name to ID resolver. It must be called
// before the allocator hands out any identity. Passing nil disables tenant
// identity partitioning, which is the state when --enable-tenancy is unset.
func (m *CachingIdentityAllocator) SetTenantIDLookup(lookup TenantIDLookup) {
	m.tenantMutex.Lock()
	defer m.tenantMutex.Unlock()
	m.tenantIDs = lookup
}

// tenantIdentityRange returns the numeric identity range and prefix mask for a
// tenant.
//
// The layout is the one ClusterMesh already uses for remote clusters: the top
// ClusterIDLen bits of a numeric identity hold the cluster ID, so reusing them
// for the tenant ID means the datapath's existing
// extract_cluster_id_from_identity() recovers the tenant with no change. The
// mask is what the allocator ORs into every ID it selects from the pool.
func tenantIdentityRange(tenantID uint32) (minID, maxID, mask idpool.ID) {
	minID = idpool.ID(identity.GetMinimalAllocationIdentity(tenantID))
	maxID = idpool.ID(identity.GetMaximumAllocationIdentity(tenantID))
	mask = idpool.ID(tenantID << identity.GetClusterIDShift())
	return minID, maxID, mask
}

// tenantIDForLabels returns the tenant an identity's label set belongs to, or 0
// for the default VPC.
func (m *CachingIdentityAllocator) tenantIDForLabels(lbls labels.Labels) uint32 {
	m.tenantMutex.RLock()
	lookup := m.tenantIDs
	m.tenantMutex.RUnlock()

	if lookup == nil {
		return 0
	}

	lbl, ok := lbls[k8sConst.PolicyLabelTenant]
	if !ok || lbl.Value == "" {
		return 0
	}
	return lookup(lbl.Value)
}

// allocatorForTenant returns the allocator that hands out identities for a
// tenant, creating it on first use.
//
// A separate allocator instance per tenant is the shape the allocator library
// supports: the ID range and the prefix mask are per-instance options, so one
// instance cannot span several ranges. Instances are created lazily because a
// node only hosts a handful of tenants in practice, and each instance carries
// its own backend and cache of the keyspace.
func (m *CachingIdentityAllocator) allocatorForTenant(tenantID uint32) (*allocator.Allocator, error) {
	if tenantID == 0 {
		return m.IdentityAllocator, nil
	}

	m.tenantMutex.RLock()
	tenancyEnabled := m.tenantIDs != nil
	a, ok := m.tenantAllocators[tenantID]
	m.tenantMutex.RUnlock()

	// With tenancy disabled a non-zero ID is a ClusterMesh cluster ID, not a
	// tenant, and those identities belong to the shared allocator's remote
	// caches. Never create a tenant allocator in that case.
	if !tenancyEnabled {
		return m.IdentityAllocator, nil
	}
	if ok {
		return a, nil
	}

	m.tenantMutex.Lock()
	defer m.tenantMutex.Unlock()

	// Another caller may have created it while this one waited for the lock.
	if a, ok := m.tenantAllocators[tenantID]; ok {
		return a, nil
	}

	if m.newTenantBackend == nil {
		return nil, fmt.Errorf("tenant identity allocator for tenant %d requested before the global allocator was initialized", tenantID)
	}

	minID, maxID, mask := tenantIdentityRange(tenantID)
	m.logger.Info("Initializing tenant identity allocator",
		logfields.TenantID, tenantID,
		logfields.Min, minID,
		logfields.Max, maxID,
	)

	backend, err := m.newTenantBackend()
	if err != nil {
		return nil, fmt.Errorf("creating identity backend for tenant %d: %w", tenantID, err)
	}

	// Feed the shared event channel, so identities allocated for this tenant on
	// other nodes reach the identity watcher and from there the SelectorCache.
	// Without this, in-tenant policy would only ever see the identities this node
	// allocated itself. The watcher does no range filtering, it just maps ID to
	// labels, so tenant identities are safe to mix into the stream.
	opts := []allocator.AllocatorOption{
		allocator.WithMin(minID),
		allocator.WithMax(maxID),
		allocator.WithPrefixMask(mask),
		allocator.WithEvents(m.events),
		allocator.WithSyncInterval(m.syncInterval),
		allocator.WithCacheValidator(clusterIDValidator(tenantID)),
	}
	if m.operatorIDManagement {
		opts = append(opts, allocator.WithOperatorIDManagement())
	} else {
		opts = append(opts, allocator.WithMasterKeyProtection())
	}
	if m.maxAllocAttempts > 0 {
		opts = append(opts, allocator.WithMaxAllocAttempts(m.maxAllocAttempts))
	}

	a, err = allocator.NewAllocator(m.logger, &key.GlobalIdentity{}, backend, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating identity allocator for tenant %d: %w", tenantID, err)
	}

	if m.tenantAllocators == nil {
		m.tenantAllocators = make(map[uint32]*allocator.Allocator)
	}
	m.tenantAllocators[tenantID] = a
	return a, nil
}

// closeTenantAllocators shuts down every per-tenant allocator.
func (m *CachingIdentityAllocator) closeTenantAllocators() {
	m.tenantMutex.Lock()
	defer m.tenantMutex.Unlock()

	for tenantID, a := range m.tenantAllocators {
		a.Delete()
		delete(m.tenantAllocators, tenantID)
	}
}

// waitForTenantIdentities blocks until the tenant's allocator has completed its
// initial sync, mirroring WaitForInitialGlobalIdentities for the shared one.
func (m *CachingIdentityAllocator) waitForTenantIdentities(ctx context.Context, a *allocator.Allocator) error {
	if err := a.WaitForInitialSync(ctx); err != nil {
		return fmt.Errorf("waiting for initial tenant identity sync: %w", err)
	}
	return nil
}
