// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package cell wires the tenancy resolver into the agent hive.
//
// It is kept separate from [github.com/cilium/cilium/pkg/tenancy] because the
// wiring needs the agent's Kubernetes StateDB tables, while the resolver itself
// is consumed by low-level packages that must not depend on them.
package cell

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmcommon "github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipseccfg "github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	k8sresources "github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tenancy"
	wgcfg "github.com/cilium/cilium/pkg/wireguard/agent"
)

// Cell resolves which tenant (VPC) a namespace belongs to and refuses startup
// when tenancy is combined with a feature it cannot work with.
//
// Every other tenancy-aware subsystem consumes the tenancy.Resolver produced
// here.
var Cell = cell.Module(
	"tenancy",
	"Overlapping-CIDR multi-tenancy namespace resolver",

	cell.Config(tenancy.DefaultConfig),

	cell.ProvidePrivate(k8sresources.CiliumTenantResource),
	cell.Provide(newTenancyResolver),

	cell.Invoke(registerTenancy),
)

// newTenancyResolver constructs the resolver. It is always provided, even with
// tenancy disabled, so consumers can depend on it unconditionally; a disabled
// resolver reports tenant 0 for every namespace.
func newTenancyResolver(cfg tenancy.Config) (tenancy.Resolver, *tenancy.NamespaceResolver) {
	r := tenancy.NewNamespaceResolver(cfg.EnableTenancy)
	return r, r
}

type tenancyParams struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	Config   tenancy.Config
	Resolver *tenancy.NamespaceResolver

	DB         *statedb.DB
	Namespaces statedb.Table[daemonk8s.Namespace]
	Tenants    resource.Resource[*cilium_api_v2alpha1.CiliumTenant]

	DaemonConfig    *option.DaemonConfig
	ClusterInfo     cmtypes.ClusterInfo
	ClusterMeshCfg  cmcommon.Config
	IPsecUserConfig ipseccfg.UserConfig
	WGUserConfig    wgcfg.UserConfig
}

func registerTenancy(p tenancyParams) error {
	if err := tenancy.ValidateIfEnabled(p.Config, tenancy.GuardInputs{
		ClusterID:            p.ClusterInfo.ID,
		MaxConnectedClusters: p.ClusterInfo.MaxConnectedClusters,
		ClusterMeshConfig:    p.ClusterMeshCfg.ClusterMeshConfig,
		RoutingMode:          p.DaemonConfig.RoutingMode,
		IPAM:                 p.DaemonConfig.IPAM,
		EnableHostFirewall:   p.DaemonConfig.EnableHostFirewall,
		EnableEgressGateway:  p.DaemonConfig.EnableEgressGateway,
		EnableIPSec:          p.IPsecUserConfig.EnableIPsec,
		EnableWireguard:      p.WGUserConfig.EnableWireguard,
		EnableVTEP:           p.DaemonConfig.EnableVTEP,
	}); err != nil {
		return err
	}

	if !p.Config.EnableTenancy {
		return nil
	}

	p.Logger.Info("Overlapping-CIDR multi-tenancy enabled")

	if p.Tenants != nil {
		p.JobGroup.Add(job.OneShot("tenancy-tenant-observer", func(ctx context.Context, _ cell.Health) error {
			return p.watchTenants(ctx)
		}))
	}

	p.JobGroup.Add(job.OneShot("tenancy-namespace-observer", func(ctx context.Context, _ cell.Health) error {
		return p.watchNamespaces(ctx)
	}))

	return nil
}

func (p tenancyParams) watchTenants(ctx context.Context) error {
	for ev := range p.Tenants.Events(ctx) {
		var err error
		switch ev.Kind {
		case resource.Upsert:
			err = p.Resolver.UpsertTenant(ev.Object.Name,
				tenantIDOf(ev.Object), ev.Object.Spec.NamespaceSelector)
			if err != nil {
				// A malformed selector is a user error; log it and drop the
				// tenant rather than retrying forever.
				p.Logger.Error("Ignoring CiliumTenant with invalid namespaceSelector",
					logfields.Error, err,
					logfields.Tenant, ev.Object.Name,
				)
				p.Resolver.DeleteTenant(ev.Object.Name)
				err = nil
			}
		case resource.Delete:
			p.Resolver.DeleteTenant(ev.Key.Name)
		}
		ev.Done(err)
	}
	return nil
}

// tenantIDOf narrows the CRD's uint32 to the uint16 the datapath maps use. The
// CRD caps the value at 255, and the operator never allocates outside
// [1, ClusterIDMax], so an out-of-range value means a hand-edited status: treat
// it as unallocated rather than truncating into another tenant's ID.
func tenantIDOf(tenant *cilium_api_v2alpha1.CiliumTenant) uint16 {
	id := tenant.Status.TenantID
	if id == 0 || id > cmtypes.ClusterIDMax {
		return 0
	}
	return uint16(id)
}

func (p tenancyParams) watchNamespaces(ctx context.Context) error {
	wtxn := p.DB.WriteTxn(p.Namespaces)
	changeIter, err := p.Namespaces.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	for {
		changes, watch := changeIter.Next(p.DB.ReadTxn())
		for change := range changes {
			if change.Deleted {
				p.Resolver.DeleteNamespace(change.Object.Name)
				continue
			}
			p.Resolver.UpsertNamespace(change.Object.Name, change.Object.Labels)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}
