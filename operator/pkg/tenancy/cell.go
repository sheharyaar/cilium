// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// Cell allocates datapath tenant IDs for CiliumTenant objects.
//
// It runs in the operator's leader-elected cells so that only one instance
// hands out IDs at a time. ID state is in-memory and rebuilt from CiliumTenant
// statuses on every leadership acquisition.
var Cell = cell.Module(
	"tenancy",
	"Allocates datapath tenant IDs for CiliumTenant objects",

	cell.Invoke(registerIDAllocator),
)

type params struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	Clientset k8sClient.Clientset
	Tenants   resource.Resource[*cilium_api_v2alpha1.CiliumTenant]
}

func registerIDAllocator(p params) {
	if !p.Clientset.IsEnabled() || p.Tenants == nil {
		return
	}

	r := newReconciler(p.Logger, p.Clientset.CiliumV2alpha1().CiliumTenants())

	p.JobGroup.Add(job.OneShot("tenancy-id-allocator", func(ctx context.Context, health cell.Health) error {
		for ev := range p.Tenants.Events(ctx) {
			ev.Done(r.handle(ctx, ev))
		}
		return nil
	}))
}
