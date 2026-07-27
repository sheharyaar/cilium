// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"context"
	"errors"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// fakeUpdater records status writes and can be made to fail.
type fakeUpdater struct {
	updates []*cilium_api_v2alpha1.CiliumTenant
	err     error
}

func (f *fakeUpdater) UpdateStatus(_ context.Context, tenant *cilium_api_v2alpha1.CiliumTenant, _ metav1.UpdateOptions) (*cilium_api_v2alpha1.CiliumTenant, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.updates = append(f.updates, tenant.DeepCopy())
	return tenant, nil
}

func (f *fakeUpdater) last() *cilium_api_v2alpha1.CiliumTenant {
	if len(f.updates) == 0 {
		return nil
	}
	return f.updates[len(f.updates)-1]
}

func tenant(name string, id uint32) *cilium_api_v2alpha1.CiliumTenant {
	return &cilium_api_v2alpha1.CiliumTenant{
		ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1},
		Status:     cilium_api_v2alpha1.TenantStatus{TenantID: id},
	}
}

func upsert(t *cilium_api_v2alpha1.CiliumTenant) resource.Event[*cilium_api_v2alpha1.CiliumTenant] {
	return resource.Event[*cilium_api_v2alpha1.CiliumTenant]{
		Kind:   resource.Upsert,
		Key:    resource.Key{Name: t.Name},
		Object: t,
	}
}

func syncEvent() resource.Event[*cilium_api_v2alpha1.CiliumTenant] {
	return resource.Event[*cilium_api_v2alpha1.CiliumTenant]{Kind: resource.Sync}
}

func deleteEvent(name string) resource.Event[*cilium_api_v2alpha1.CiliumTenant] {
	return resource.Event[*cilium_api_v2alpha1.CiliumTenant]{
		Kind: resource.Delete,
		Key:  resource.Key{Name: name},
	}
}

func newTestReconciler(t *testing.T) (*reconciler, *fakeUpdater) {
	t.Helper()
	up := &fakeUpdater{}
	return newReconciler(hivetest.Logger(t), up), up
}

func TestReconcilerAllocatesAfterSync(t *testing.T) {
	ctx := context.Background()
	r, up := newTestReconciler(t)

	require.NoError(t, r.handle(ctx, upsert(tenant("acme", 0))))
	// Nothing is written before the sync event: pre-existing IDs must be
	// reserved first.
	require.Empty(t, up.updates)

	require.NoError(t, r.handle(ctx, syncEvent()))
	require.Len(t, up.updates, 1)
	require.Equal(t, uint32(1), up.last().Status.TenantID)
	require.Equal(t, "acme", up.last().Name)
}

func TestReconcilerRestoreBeforeAllocate(t *testing.T) {
	ctx := context.Background()
	r, up := newTestReconciler(t)

	// globex already holds ID 1; acme has none yet. acme must not steal 1.
	require.NoError(t, r.handle(ctx, upsert(tenant("acme", 0))))
	require.NoError(t, r.handle(ctx, upsert(tenant("globex", 1))))
	require.Empty(t, up.updates, "restored tenants need no status write")

	require.NoError(t, r.handle(ctx, syncEvent()))
	require.Len(t, up.updates, 1)
	require.Equal(t, "acme", up.last().Name)
	require.Equal(t, uint32(2), up.last().Status.TenantID)
}

func TestReconcilerSetsAllocatedCondition(t *testing.T) {
	ctx := context.Background()
	r, up := newTestReconciler(t)

	require.NoError(t, r.handle(ctx, syncEvent()))
	require.NoError(t, r.handle(ctx, upsert(tenant("acme", 0))))

	got := up.last()
	require.NotNil(t, got)
	require.Len(t, got.Status.Conditions, 1)
	cond := got.Status.Conditions[0]
	require.Equal(t, cilium_api_v2alpha1.TenantConditionIDAllocated, cond.Type)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, cilium_api_v2alpha1.TenantReasonAllocated, cond.Reason)
	require.Equal(t, int64(1), cond.ObservedGeneration)
}

func TestReconcilerExhaustionCondition(t *testing.T) {
	ctx := context.Background()
	r, up := newTestReconciler(t)
	require.NoError(t, r.handle(ctx, syncEvent()))

	// Drain the whole ID space.
	for i := uint32(1); i <= 255; i++ {
		require.NoError(t, r.ids.restore(i))
	}

	require.NoError(t, r.handle(ctx, upsert(tenant("late", 0))),
		"exhaustion must not be retried as a transient error")

	got := up.last()
	require.NotNil(t, got)
	require.Equal(t, uint32(0), got.Status.TenantID)
	require.Len(t, got.Status.Conditions, 1)
	require.Equal(t, metav1.ConditionFalse, got.Status.Conditions[0].Status)
	require.Equal(t, cilium_api_v2alpha1.TenantReasonExhausted, got.Status.Conditions[0].Reason)
}

func TestReconcilerDeleteReleasesID(t *testing.T) {
	ctx := context.Background()
	r, up := newTestReconciler(t)
	require.NoError(t, r.handle(ctx, syncEvent()))

	require.NoError(t, r.handle(ctx, upsert(tenant("acme", 0))))
	require.Equal(t, uint32(1), up.last().Status.TenantID)

	require.NoError(t, r.handle(ctx, deleteEvent("acme")))

	// The freed ID is handed to the next tenant.
	require.NoError(t, r.handle(ctx, upsert(tenant("globex", 0))))
	require.Equal(t, uint32(1), up.last().Status.TenantID)
}

func TestReconcilerDuplicateIDIsReallocated(t *testing.T) {
	ctx := context.Background()
	r, up := newTestReconciler(t)

	require.NoError(t, r.handle(ctx, upsert(tenant("acme", 5))))
	// Second tenant records the same ID: first wins, second is reallocated.
	require.NoError(t, r.handle(ctx, upsert(tenant("globex", 5))))

	got := up.last()
	require.NotNil(t, got)
	require.Equal(t, "globex", got.Name)
	require.NotEqual(t, uint32(5), got.Status.TenantID)
	require.NotEqual(t, uint32(0), got.Status.TenantID)
}

func TestReconcilerStatusWriteFailureDoesNotLeakID(t *testing.T) {
	ctx := context.Background()
	r, up := newTestReconciler(t)
	require.NoError(t, r.handle(ctx, syncEvent()))

	up.err = errors.New("boom")
	require.Error(t, r.handle(ctx, upsert(tenant("acme", 0))))
	require.False(t, r.ids.isUsed(1), "failed allocation must be released")

	// A retry succeeds and reuses the same ID.
	up.err = nil
	require.NoError(t, r.handle(ctx, upsert(tenant("acme", 0))))
	require.Equal(t, uint32(1), up.last().Status.TenantID)
}

func TestReconcilerIdempotentUpsertOfRestoredTenant(t *testing.T) {
	ctx := context.Background()
	r, up := newTestReconciler(t)

	require.NoError(t, r.handle(ctx, upsert(tenant("acme", 9))))
	// A resync of the same object must not conflict with itself.
	require.NoError(t, r.handle(ctx, upsert(tenant("acme", 9))))
	require.Empty(t, up.updates)
	require.True(t, r.ids.isUsed(9))
}
