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
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmcommon "github.com/cilium/cilium/pkg/clustermesh/common"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipseccfg "github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	"github.com/cilium/cilium/pkg/identity/cache"
	identitycachecell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	k8sresources "github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8stypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
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

	Logger    *slog.Logger
	JobGroup  job.Group
	Lifecycle cell.Lifecycle

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
	IdentityCfg     identitycachecell.SharedConfig

	IdentityAllocator identitycachecell.CachingIdentityAllocator

	IPCache         *ipcache.IPCache
	CiliumEndpoints resource.Resource[*k8stypes.CiliumEndpoint]
}

// perTenantCTMaps builds the per-tenant conntrack map manager and ties its outer
// maps to the agent lifecycle. Returns an inert reconciler when tenancy is off.
func perTenantCTMaps(p tenancyParams) *tenantCTMaps {
	if !p.Config.EnableTenancy {
		return newTenantCTMaps(p.Logger, nil)
	}

	// IPv6 is refused alongside tenancy, so only the v4 maps are managed.
	maps := ctmap.NewPerClusterCTMaps(true, false)

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			// The outer maps must exist before any tenant's inner map can be
			// inserted, and before the datapath looks one up.
			if err := maps.OpenOrCreate(); err != nil {
				return fmt.Errorf("creating per-tenant conntrack maps: %w", err)
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			return maps.Close()
		},
	})

	return newTenantCTMaps(p.Logger, maps)
}

// tenantIDLookupSetter is implemented by the concrete caching identity
// allocator. It is asserted rather than added to the CachingIdentityAllocator
// interface so that the mock allocators used in tests do not all have to grow
// the method.
type tenantIDLookupSetter interface {
	SetTenantIDLookup(cache.TenantIDLookup)
}

func registerTenancy(p tenancyParams) error {
	if err := tenancy.ValidateIfEnabled(p.Config, tenancy.GuardInputs{
		ClusterID:              p.ClusterInfo.ID,
		MaxConnectedClusters:   p.ClusterInfo.MaxConnectedClusters,
		ClusterMeshConfig:      p.ClusterMeshCfg.ClusterMeshConfig,
		RoutingMode:            p.DaemonConfig.RoutingMode,
		IPAM:                   p.DaemonConfig.IPAM,
		IdentityManagementMode: p.IdentityCfg.IdentityManagementMode,
		IdentityAllocationMode: p.DaemonConfig.IdentityAllocationMode,
		EnableIPv6:             p.DaemonConfig.EnableIPv6,
		EnableHostFirewall:     p.DaemonConfig.EnableHostFirewall,
		EnableEgressGateway:    p.DaemonConfig.EnableEgressGateway,
		EnableIPSec:            p.IPsecUserConfig.EnableIPsec,
		EnableWireguard:        p.WGUserConfig.EnableWireguard,
		EnableVTEP:             p.DaemonConfig.EnableVTEP,
	}); err != nil {
		return err
	}

	if !p.Config.EnableTenancy {
		return nil
	}

	p.Logger.Info("Overlapping-CIDR multi-tenancy enabled")

	// Teach the identity allocator how to turn the tenant name carried in an
	// identity's labels into the tenant ID the datapath encodes, so tenant
	// identities are allocated from their tenant's numeric range.
	if setter, ok := p.IdentityAllocator.(tenantIDLookupSetter); ok {
		setter.SetTenantIDLookup(func(name string) uint32 {
			return uint32(p.Resolver.TenantIDForName(name))
		})
	} else {
		return fmt.Errorf("identity allocator %T does not support tenant identity ranges", p.IdentityAllocator)
	}

	ctMaps := perTenantCTMaps(p)
	gateways := newTenantGateways(p.Logger, p.IPCache)

	if p.Tenants != nil {
		p.JobGroup.Add(job.OneShot("tenancy-tenant-observer", func(ctx context.Context, _ cell.Health) error {
			return p.watchTenants(ctx, ctMaps, gateways)
		}))
	}

	if p.CiliumEndpoints != nil {
		p.JobGroup.Add(job.OneShot("tenancy-gateway-observer", func(ctx context.Context, _ cell.Health) error {
			return p.watchGatewayEndpoints(ctx, gateways)
		}))
	}

	p.JobGroup.Add(job.OneShot("tenancy-namespace-observer", func(ctx context.Context, _ cell.Health) error {
		return p.watchNamespaces(ctx)
	}))

	return nil
}

func (p tenancyParams) watchTenants(ctx context.Context, ctMaps *tenantCTMaps, gateways *tenantGateways) error {
	for ev := range p.Tenants.Events(ctx) {
		var err error
		switch ev.Kind {
		case resource.Upsert:
			tenantID := tenantIDOf(ev.Object)

			// The conntrack maps must exist before the resolver hands this
			// tenant out, otherwise an endpoint could be created in a tenant
			// whose map the datapath cannot find. Retry on failure.
			if err = ctMaps.ensure(uint32(tenantID)); err != nil {
				ev.Done(err)
				continue
			}

			if gwErr := p.updateGateway(gateways, ev.Object, tenantID); gwErr != nil {
				// A malformed gateway selector must not stop the tenant from
				// being usable for everything else.
				p.Logger.Error("Ignoring CiliumTenant egressGateway",
					logfields.Error, gwErr,
					logfields.Tenant, ev.Object.Name,
				)
			}

			err = p.Resolver.UpsertTenant(ev.Object.Name,
				tenantID, ev.Object.Spec.NamespaceSelector)
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
			// Stop handing the tenant out first, then drop its maps, so no
			// endpoint can be placed in a tenant whose maps just went away.
			tenantID := p.Resolver.TenantIDForName(ev.Key.Name)
			gateways.deleteTenant(ev.Key.Name)
			p.Resolver.DeleteTenant(ev.Key.Name)
			err = ctMaps.remove(uint32(tenantID))
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

// updateGateway hands the tenant's egress gateway selection to the reconciler.
func (p tenancyParams) updateGateway(gateways *tenantGateways,
	tenant *cilium_api_v2alpha1.CiliumTenant, tenantID uint16) error {
	var (
		namespace string
		selector  *slim_metav1.LabelSelector
	)
	if gw := tenant.Spec.EgressGateway; gw != nil {
		namespace = gw.Namespace
		selector = gw.PodSelector
	}

	spec, err := parseGatewaySpec(tenant.Name, namespace, selector)
	if err != nil {
		// Still register the tenant, without a gateway, so a later fix is
		// picked up and the tenant is not left half-known.
		_ = gateways.upsertTenant(tenant.Name, tenantID, nil)
		return err
	}

	return gateways.upsertTenant(tenant.Name, tenantID, spec)
}

// watchGatewayEndpoints feeds CiliumEndpoints to the gateway reconciler.
//
// CiliumEndpoints are used rather than pods because the agent sees them
// cluster-wide, and a tenant's gateway may run on any node. They also already
// carry the node IP and the security identity the ipcache entry needs.
func (p tenancyParams) watchGatewayEndpoints(ctx context.Context, gateways *tenantGateways) error {
	for ev := range p.CiliumEndpoints.Events(ctx) {
		var err error

		switch ev.Kind {
		case resource.Upsert:
			err = gateways.upsertEndpoint(gatewayCandidateOf(ev.Object))
		case resource.Delete:
			err = gateways.deleteEndpoint(ev.Key.Namespace, ev.Key.Name)
		}

		if err != nil {
			p.Logger.Error("Failed to reconcile tenant egress gateway",
				logfields.Error, err,
			)
			// Reconciliation is retried on the next event rather than by
			// requeuing this one: the reconciler recomputes from full state,
			// so a stale event adds nothing.
			err = nil
		}
		ev.Done(err)
	}
	return nil
}

func gatewayCandidateOf(cep *k8stypes.CiliumEndpoint) gatewayCandidate {
	c := gatewayCandidate{
		namespace: cep.Namespace,
		name:      cep.Name,
		labels:    cep.Labels,
	}

	if cep.Identity != nil {
		c.identity = uint32(cep.Identity.ID)
	}
	if cep.Networking != nil {
		c.nodeIP = cep.Networking.NodeIP
		for _, pair := range cep.Networking.Addressing {
			if pair.IPV4 != "" {
				c.podIP = pair.IPV4
				break
			}
		}
	}
	return c
}
