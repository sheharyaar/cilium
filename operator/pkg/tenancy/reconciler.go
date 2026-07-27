// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"context"
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// tenantStatusUpdater is the subset of the generated CiliumTenant client the
// reconciler needs. It exists so tests can drive the reconciler with a fake.
type tenantStatusUpdater interface {
	UpdateStatus(ctx context.Context, tenant *cilium_api_v2alpha1.CiliumTenant, opts metav1.UpdateOptions) (*cilium_api_v2alpha1.CiliumTenant, error)
}

// reconciler allocates a datapath tenant ID for every CiliumTenant and writes
// it to the tenant's status.
//
// Ordering matters: every ID already recorded in a status must be reserved
// before any new ID is handed out, otherwise a tenant listed later in the
// initial sync could have its ID stolen. Tenants seen before the sync event
// that still need an ID are therefore queued and only allocated once the store
// has been fully synchronized.
type reconciler struct {
	logger  *slog.Logger
	tenants tenantStatusUpdater

	ids *idAllocator

	// assigned tracks the ID this reconciler believes each tenant holds, so a
	// delete event can release the right ID.
	assigned map[string]uint32

	// pending holds tenants observed before the sync event that have no ID yet.
	pending map[string]*cilium_api_v2alpha1.CiliumTenant

	synced bool
}

func newReconciler(logger *slog.Logger, tenants tenantStatusUpdater) *reconciler {
	return &reconciler{
		logger:   logger,
		tenants:  tenants,
		ids:      newIDAllocator(),
		assigned: make(map[string]uint32),
		pending:  make(map[string]*cilium_api_v2alpha1.CiliumTenant),
	}
}

// handle processes a single CiliumTenant event. The returned error is passed
// back to the resource machinery, which retries the event.
func (r *reconciler) handle(ctx context.Context, ev resource.Event[*cilium_api_v2alpha1.CiliumTenant]) error {
	switch ev.Kind {
	case resource.Sync:
		return r.drainPending(ctx)
	case resource.Upsert:
		return r.upsert(ctx, ev.Object)
	case resource.Delete:
		r.delete(ev.Key.Name)
		return nil
	}
	return nil
}

func (r *reconciler) upsert(ctx context.Context, tenant *cilium_api_v2alpha1.CiliumTenant) error {
	name := tenant.Name

	if id := tenant.Status.TenantID; id != 0 {
		// The tenant already carries an ID. Reserve it once; a conflict means
		// two tenants recorded the same ID, in which case the first one wins
		// and this tenant is re-allocated.
		if known, ok := r.assigned[name]; ok && known == id {
			return nil
		}
		if err := r.ids.restore(id); err != nil {
			r.logger.WarnContext(ctx, "Reallocating conflicting tenant ID",
				logfields.Error, err,
				logfields.Tenant, name,
				logfields.TenantID, id,
			)
			delete(r.assigned, name)
			return r.allocateFor(ctx, tenant)
		}
		r.assigned[name] = id
		return nil
	}

	if !r.synced {
		// Defer until every pre-existing ID has been reserved.
		r.pending[name] = tenant
		return nil
	}

	return r.allocateFor(ctx, tenant)
}

func (r *reconciler) drainPending(ctx context.Context) error {
	r.synced = true

	var errs error
	for name, tenant := range r.pending {
		if err := r.allocateFor(ctx, tenant); err != nil {
			// Keep the tenant queued so a retry of the sync event picks it up.
			errs = fmt.Errorf("allocating tenant %q: %w", name, err)
			continue
		}
		delete(r.pending, name)
	}
	return errs
}

func (r *reconciler) allocateFor(ctx context.Context, cached *cilium_api_v2alpha1.CiliumTenant) error {
	// Never mutate the object owned by the informer store.
	tenant := cached.DeepCopy()

	id, err := r.ids.allocate()
	if err != nil {
		// Exhaustion is a terminal condition, not a transient error: report it
		// on the tenant and do not retry.
		r.setCondition(tenant, metav1.Condition{
			Type:    cilium_api_v2alpha1.TenantConditionIDAllocated,
			Status:  metav1.ConditionFalse,
			Reason:  cilium_api_v2alpha1.TenantReasonExhausted,
			Message: err.Error(),
		})
		if updateErr := r.updateStatus(ctx, tenant); updateErr != nil {
			return updateErr
		}
		r.logger.ErrorContext(ctx, "No tenant ID available",
			logfields.Error, err,
			logfields.Tenant, tenant.Name,
		)
		return nil
	}

	tenant.Status.TenantID = id
	r.setCondition(tenant, metav1.Condition{
		Type:    cilium_api_v2alpha1.TenantConditionIDAllocated,
		Status:  metav1.ConditionTrue,
		Reason:  cilium_api_v2alpha1.TenantReasonAllocated,
		Message: fmt.Sprintf("Allocated tenant ID %d", id),
	})

	if err := r.updateStatus(ctx, tenant); err != nil {
		// Hand the ID back so a retry does not leak it.
		r.ids.release(id)
		return err
	}

	r.assigned[tenant.Name] = id
	r.logger.InfoContext(ctx, "Allocated tenant ID",
		logfields.Tenant, tenant.Name,
		logfields.TenantID, id,
	)
	return nil
}

func (r *reconciler) delete(name string) {
	if id, ok := r.assigned[name]; ok {
		r.ids.release(id)
		delete(r.assigned, name)
	}
	delete(r.pending, name)
}

func (r *reconciler) setCondition(tenant *cilium_api_v2alpha1.CiliumTenant, cond metav1.Condition) {
	cond.ObservedGeneration = tenant.Generation
	meta.SetStatusCondition(&tenant.Status.Conditions, cond)
}

func (r *reconciler) updateStatus(ctx context.Context, tenant *cilium_api_v2alpha1.CiliumTenant) error {
	_, err := r.tenants.UpdateStatus(ctx, tenant, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating CiliumTenant %q status: %w", tenant.Name, err)
	}
	return nil
}
