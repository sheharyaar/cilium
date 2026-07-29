// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/tenancy"
)

// fakeCTMaps records the calls the reconciler makes, in order.
type fakeCTMaps struct {
	created []uint32
	deleted []uint32
	err     error
}

func (f *fakeCTMaps) CreateClusterCTMaps(id uint32) error {
	if f.err != nil {
		return f.err
	}
	f.created = append(f.created, id)
	return nil
}

func (f *fakeCTMaps) DeleteClusterCTMaps(id uint32) error {
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func newTestCTReconciler(t *testing.T) (*tenantCTMaps, *fakeCTMaps, *tenancy.NamespaceResolver) {
	t.Helper()
	maps := &fakeCTMaps{}
	resolver := tenancy.NewNamespaceResolver(true)
	return newTenantCTMaps(hivetest.Logger(t), maps, nil), maps, resolver
}

func TestTenantCTMapsCreateIsIdempotent(t *testing.T) {
	r, maps, _ := newTestCTReconciler(t)

	require.NoError(t, r.ensure(3))
	require.NoError(t, r.ensure(3))
	require.NoError(t, r.ensure(4))

	// A resync of the same tenant must not recreate its maps.
	assert.Equal(t, []uint32{3, 4}, maps.created)
}

func TestTenantCTMapsDelete(t *testing.T) {
	r, maps, _ := newTestCTReconciler(t)

	require.NoError(t, r.ensure(3))
	require.NoError(t, r.remove(3))
	assert.Equal(t, []uint32{3}, maps.deleted)

	// Deleting a tenant whose maps were never created is a no-op, not an error:
	// a delete event can arrive for a tenant that never had an allocated ID.
	require.NoError(t, r.remove(9))
	assert.Equal(t, []uint32{3}, maps.deleted)

	// After removal the tenant can come back.
	require.NoError(t, r.ensure(3))
	assert.Equal(t, []uint32{3, 3}, maps.created)
}

func TestTenantCTMapsIgnoresDefaultVPC(t *testing.T) {
	r, maps, _ := newTestCTReconciler(t)

	// Tenant 0 is the default VPC and uses the global CT maps, so it must never
	// get an inner map. Creating one at index 0 would shadow nothing but would
	// suggest the global maps are unused.
	require.NoError(t, r.ensure(0))
	require.NoError(t, r.remove(0))

	assert.Empty(t, maps.created)
	assert.Empty(t, maps.deleted)
}

func TestTenantCTMapsCreateFailureIsNotRecorded(t *testing.T) {
	r, maps, _ := newTestCTReconciler(t)
	maps.err = errors.New("boom")

	require.Error(t, r.ensure(3))

	// The failure must not be remembered as success, or a retry would skip
	// creating the map and the tenant's traffic would land in the global CT map.
	maps.err = nil
	require.NoError(t, r.ensure(3))
	assert.Equal(t, []uint32{3}, maps.created)
}

func TestTenantCTMapsDisabled(t *testing.T) {
	// With no manager the reconciler is inert, which is the state when tenancy
	// is off.
	r := newTenantCTMaps(hivetest.Logger(t), nil, nil)
	require.NoError(t, r.ensure(3))
	require.NoError(t, r.remove(3))
}

// The garbage collector takes the per-cluster conntrack maps through an
// optional hive dependency that nothing else in the tree provides. If this cell
// stops providing it, the per-tenant maps are created and never collected, and
// their LRU starts evicting live-but-idle connections to make room for dead
// ones. The failure is silent and slow, so assert the wiring rather than
// trusting it.
func TestPerTenantCTMapsProvidesGCRetriever(t *testing.T) {
	// Disabled is the case that can be exercised without BPF privileges. The
	// retriever must still be non-nil so the hive graph resolves for every
	// deployment, not only tenancy ones.
	out := perTenantCTMaps(ctMapParams{
		Logger:    hivetest.Logger(t),
		Lifecycle: &fakeLifecycle{},
		Config:    tenancy.Config{EnableTenancy: false},
	})

	require.NotNil(t, out.Maps)
	require.NotNil(t, out.Retriever, "GC would silently stop collecting per-tenant conntrack maps")
	assert.Empty(t, out.Retriever(), "no tenants means nothing to collect")
}

// fakeLifecycle accepts hooks without running them.
type fakeLifecycle struct{ hooks []cell.HookInterface }

func (f *fakeLifecycle) Append(h cell.HookInterface)               { f.hooks = append(f.hooks, h) }
func (f *fakeLifecycle) Start(*slog.Logger, context.Context) error { return nil }
func (f *fakeLifecycle) Stop(*slog.Logger, context.Context) error  { return nil }
func (f *fakeLifecycle) PrintHooks(io.Writer)                      {}
