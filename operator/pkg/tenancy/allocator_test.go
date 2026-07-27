// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestIDAllocatorRestore(t *testing.T) {
	a := newIDAllocator()

	// IDs recovered from an existing CiliumTenant status are reserved.
	require.NoError(t, a.restore(7))
	require.True(t, a.isUsed(7))

	// Re-restoring the same ID is a conflict, not a no-op: two tenants must
	// never share a datapath ID.
	require.Error(t, a.restore(7))

	// Out of range.
	require.Error(t, a.restore(0))
	require.Error(t, a.restore(cmtypes.ClusterIDMax+1))
}

func TestIDAllocatorAllocateSkipsRestored(t *testing.T) {
	a := newIDAllocator()
	require.NoError(t, a.restore(1))
	require.NoError(t, a.restore(2))

	id, err := a.allocate()
	require.NoError(t, err)
	require.Equal(t, uint32(3), id)

	id, err = a.allocate()
	require.NoError(t, err)
	require.Equal(t, uint32(4), id)
}

func TestIDAllocatorExhaustion(t *testing.T) {
	a := newIDAllocator()
	for i := uint32(1); i <= cmtypes.ClusterIDMax; i++ {
		require.NoError(t, a.restore(i))
	}

	_, err := a.allocate()
	require.ErrorIs(t, err, errTenantIDsExhausted)
}

func TestIDAllocatorReleaseFrees(t *testing.T) {
	a := newIDAllocator()
	for i := uint32(1); i <= cmtypes.ClusterIDMax; i++ {
		require.NoError(t, a.restore(i))
	}

	a.release(42)
	id, err := a.allocate()
	require.NoError(t, err)
	require.Equal(t, uint32(42), id)

	// Releasing an unknown ID is a no-op.
	a.release(0)
	a.release(1000)
}
