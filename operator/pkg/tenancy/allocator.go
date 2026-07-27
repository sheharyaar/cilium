// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"errors"
	"fmt"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/lock"
)

var errTenantIDsExhausted = errors.New("all tenant IDs are in use")

// idAllocator hands out datapath tenant IDs in the range [1, ClusterIDMax].
//
// The tenant ID occupies the same bits as a ClusterMesh cluster ID, so the two
// features share one ID space and are mutually exclusive (enforced by the agent
// startup guards). ID 0 is reserved for the default VPC.
//
// State is kept in memory only and is rebuilt from CiliumTenant statuses on
// startup via restore(); the CRD is the source of truth.
type idAllocator struct {
	mu   lock.Mutex
	used map[uint32]struct{}
}

func newIDAllocator() *idAllocator {
	return &idAllocator{used: make(map[uint32]struct{})}
}

// restore reserves an ID that was already recorded in a CiliumTenant status.
// It returns an error if the ID is out of range or already reserved, which
// indicates two tenants sharing a datapath ID.
func (a *idAllocator) restore(id uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if id == 0 || id > cmtypes.ClusterIDMax {
		return fmt.Errorf("tenant ID %d out of range 1-%d", id, cmtypes.ClusterIDMax)
	}
	if _, ok := a.used[id]; ok {
		return fmt.Errorf("tenant ID %d already reserved", id)
	}
	a.used[id] = struct{}{}
	return nil
}

// allocate returns the lowest free tenant ID.
func (a *idAllocator) allocate() (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for id := uint32(1); id <= cmtypes.ClusterIDMax; id++ {
		if _, ok := a.used[id]; !ok {
			a.used[id] = struct{}{}
			return id, nil
		}
	}
	return 0, errTenantIDsExhausted
}

// release returns an ID to the pool. Releasing an ID that is not held is a
// no-op so that duplicate delete events are harmless.
func (a *idAllocator) release(id uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.used, id)
}

func (a *idAllocator) isUsed(id uint32) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	_, ok := a.used[id]
	return ok
}
