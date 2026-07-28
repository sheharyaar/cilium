// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"errors"
	"fmt"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

// GuardInputs is the configuration tenancy must be compatible with. It is a
// plain struct rather than a set of injected configs so the rules can be tested
// without standing up a hive.
type GuardInputs struct {
	ClusterID              uint32
	MaxConnectedClusters   uint32
	ClusterMeshConfig      string
	RoutingMode            string
	IPAM                   string
	IdentityManagementMode string
	IdentityAllocationMode string

	EnableIPv6          bool
	EnableHostFirewall  bool
	EnableEgressGateway bool
	EnableIPSec         bool
	EnableWireguard     bool
	EnableVTEP          bool
}

func ValidateIfEnabled(cfg Config, in GuardInputs) error {
	if !cfg.EnableTenancy {
		return nil
	}
	return Validate(in)
}

// Validate reports every reason tenancy cannot run with the given
// configuration. All conflicts are collected so that a misconfigured deployment
// learns about them in one go instead of one agent restart at a time.
func Validate(in GuardInputs) error {
	var errs []error

	// A tenant ID and a ClusterMesh cluster ID are the same datapath bits, so
	// the two features cannot coexist.
	if in.ClusterID != 0 || in.ClusterMeshConfig != "" {
		errs = append(errs, fmt.Errorf(
			"--%s cannot be used with ClusterMesh: a tenant ID shares its ID space with ClusterMesh cluster IDs (cluster-id=%d, clustermesh-config=%q)",
			EnableTenancy, in.ClusterID, in.ClusterMeshConfig))
	}

	// The tenant ID range and the identity bit layout are both derived from
	// ClusterIDMax. Pin it to the default so a tenant's identity range cannot
	// silently move.
	if in.MaxConnectedClusters != defaults.MaxConnectedClusters {
		errs = append(errs, fmt.Errorf(
			"--%s requires --%s=%d, got %d: the tenant ID range and the identity bit layout are derived from it",
			EnableTenancy, cmtypes.OptMaxConnectedClusters, defaults.MaxConnectedClusters, in.MaxConnectedClusters))
	}

	// Native routing cannot disambiguate overlapping pod IPs: the tenant is
	// only recoverable from the tunnel's security identity.
	if in.RoutingMode != option.RoutingModeTunnel {
		errs = append(errs, fmt.Errorf(
			"--%s requires --%s=%s, got %q: overlapping pod IPs cannot be disambiguated without encapsulation",
			EnableTenancy, option.RoutingMode, option.RoutingModeTunnel, in.RoutingMode))
	}

	// Only multi-pool IPAM can hand out per-tenant pools.
	if in.IPAM != ipamOption.IPAMMultiPool {
		errs = append(errs, fmt.Errorf(
			"--%s requires --%s=%s, got %q",
			EnableTenancy, option.IPAM, ipamOption.IPAMMultiPool, in.IPAM))
	}

	// Cross-node propagation of a tenant pod IP goes through the CiliumEndpoint
	// watcher, which annotates the ipcache key with the tenant. The kvstore IP to
	// identity syncher takes a bare address and has no tenant to annotate with,
	// so in a kvstore mode remote agents would learn tenant pod IPs as belonging
	// to the default VPC.
	if in.IdentityAllocationMode != option.IdentityAllocationModeCRD {
		errs = append(errs, fmt.Errorf(
			"--%s requires --%s=%s, got %q: the kvstore IP to identity syncher cannot carry a tenant",
			EnableTenancy, option.IdentityAllocationMode, option.IdentityAllocationModeCRD, in.IdentityAllocationMode))
	}

	// The tenant label is injected into identity labels by the agent, which is
	// the only component with a tenancy resolver. If the operator also manages
	// CiliumIdentities it would compute the same pod's labels without the tenant
	// label and fight the agent over the identity.
	if in.IdentityManagementMode != option.IdentityManagementModeAgent {
		errs = append(errs, fmt.Errorf(
			"--%s requires --%s=%s, got %q: only the agent can resolve a pod's tenant, so an operator-managed identity would be missing the tenant label",
			EnableTenancy, option.IdentityManagementMode, option.IdentityManagementModeAgent, in.IdentityManagementMode))
	}

	// The prototype datapath converts the IPv4 lookups only. Their IPv6 twins
	// still resolve at cluster ID 0, so v6 traffic would silently see the default
	// VPC's view of a tenant IP. Refuse rather than leak.
	if in.EnableIPv6 {
		errs = append(errs, fmt.Errorf(
			"--%s does not support IPv6 yet: the IPv6 datapath lookups are not tenant aware and would resolve against the default VPC",
			EnableTenancy))
	}

	// The features below resolve IPs against the ipcache at cluster ID 0 only,
	// so they would silently read the default VPC's view of a tenant IP.
	for _, conflict := range []struct {
		enabled bool
		flag    string
		what    string
	}{
		{in.EnableHostFirewall, option.EnableHostFirewall, "the host firewall resolves identities at cluster ID 0"},
		{in.EnableEgressGateway, option.EnableEgressGateway, "the egress gateway resolves identities at cluster ID 0"},
		{in.EnableIPSec, "enable-ipsec", "IPsec resolves identities at cluster ID 0"},
		{in.EnableWireguard, "enable-wireguard", "WireGuard resolves identities at cluster ID 0"},
		{in.EnableVTEP, option.EnableVTEP, "VTEP integration resolves endpoints without a tenant"},
	} {
		if conflict.enabled {
			errs = append(errs, fmt.Errorf("--%s cannot be used with --%s: %s",
				EnableTenancy, conflict.flag, conflict.what))
		}
	}

	return errors.Join(errs...)
}
