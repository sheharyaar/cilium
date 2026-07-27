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

// guardInputs is the configuration tenancy must be compatible with. It is a
// plain struct rather than a set of injected configs so the rules can be tested
// without standing up a hive.
type guardInputs struct {
	ClusterID            uint32
	MaxConnectedClusters uint32
	ClusterMeshConfig    string
	RoutingMode          string
	IPAM                 string

	EnableHostFirewall  bool
	EnableEgressGateway bool
	EnableIPSec         bool
	EnableWireguard     bool
	EnableVTEP          bool
}

func validateIfEnabled(cfg Config, in guardInputs) error {
	if !cfg.EnableTenancy {
		return nil
	}
	return validate(in)
}

// validate reports every reason tenancy cannot run with the given
// configuration. All conflicts are collected so that a misconfigured deployment
// learns about them in one go instead of one agent restart at a time.
func validate(in guardInputs) error {
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
