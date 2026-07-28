// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

// validInputs is the minimal configuration tenancy supports.
func validInputs() GuardInputs {
	return GuardInputs{
		ClusterID:              0,
		MaxConnectedClusters:   cmtypes.DefaultClusterInfo.MaxConnectedClusters,
		ClusterMeshConfig:      "",
		RoutingMode:            option.RoutingModeTunnel,
		IPAM:                   ipamOption.IPAMMultiPool,
		IdentityManagementMode: option.IdentityManagementModeAgent,
		IdentityAllocationMode: option.IdentityAllocationModeCRD,
	}
}

func TestGuardsAcceptSupportedConfig(t *testing.T) {
	require.NoError(t, Validate(validInputs()))
}

func TestGuardsDisabledSkipsEverything(t *testing.T) {
	// With tenancy off nothing is validated: an unrelated deployment must not
	// start failing because these guards exist.
	in := validInputs()
	in.RoutingMode = option.RoutingModeNative
	in.IPAM = ipamOption.IPAMKubernetes
	in.EnableIPSec = true
	in.ClusterID = 7

	require.NoError(t, ValidateIfEnabled(Config{EnableTenancy: false}, in))
	require.Error(t, ValidateIfEnabled(Config{EnableTenancy: true}, in))
}

func TestGuardsRejectConflicts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*GuardInputs)
		errMsg string
	}{
		{
			name:   "clustermesh cluster ID",
			mutate: func(in *GuardInputs) { in.ClusterID = 3 },
			errMsg: "shares its ID space with ClusterMesh",
		},
		{
			name:   "clustermesh config directory",
			mutate: func(in *GuardInputs) { in.ClusterMeshConfig = "/var/lib/cilium/clustermesh" },
			errMsg: "shares its ID space with ClusterMesh",
		},
		{
			name:   "native routing",
			mutate: func(in *GuardInputs) { in.RoutingMode = option.RoutingModeNative },
			errMsg: "requires --routing-mode=tunnel",
		},
		{
			name:   "non multi-pool IPAM",
			mutate: func(in *GuardInputs) { in.IPAM = ipamOption.IPAMKubernetes },
			errMsg: "requires --ipam=multi-pool",
		},
		{
			name:   "ipv6 enabled",
			mutate: func(in *GuardInputs) { in.EnableIPv6 = true },
			errMsg: "does not support IPv6 yet",
		},
		{
			name:   "host firewall",
			mutate: func(in *GuardInputs) { in.EnableHostFirewall = true },
			errMsg: "host firewall",
		},
		{
			name:   "egress gateway",
			mutate: func(in *GuardInputs) { in.EnableEgressGateway = true },
			errMsg: "egress gateway",
		},
		{
			name:   "ipsec",
			mutate: func(in *GuardInputs) { in.EnableIPSec = true },
			errMsg: "IPsec",
		},
		{
			name:   "wireguard",
			mutate: func(in *GuardInputs) { in.EnableWireguard = true },
			errMsg: "WireGuard",
		},
		{
			name:   "vtep",
			mutate: func(in *GuardInputs) { in.EnableVTEP = true },
			errMsg: "VTEP",
		},
		{
			name:   "non-default max connected clusters",
			mutate: func(in *GuardInputs) { in.MaxConnectedClusters = 511 },
			errMsg: "--max-connected-clusters",
		},
		{
			// Only the agent can resolve a pod's tenant, so an
			// operator-managed identity would lack the tenant label and the two
			// would fight over the same pod's identity.
			name:   "operator-managed identities",
			mutate: func(in *GuardInputs) { in.IdentityManagementMode = option.IdentityManagementModeOperator },
			errMsg: "--identity-management-mode=agent",
		},
		{
			name:   "kvstore identity allocation",
			mutate: func(in *GuardInputs) { in.IdentityAllocationMode = option.IdentityAllocationModeKVstore },
			errMsg: "--identity-allocation-mode=crd",
		},
		{
			name:   "identities managed by both",
			mutate: func(in *GuardInputs) { in.IdentityManagementMode = option.IdentityManagementModeBoth },
			errMsg: "--identity-management-mode=agent",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := validInputs()
			tc.mutate(&in)
			err := Validate(in)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errMsg)
		})
	}
}

func TestGuardsReportAllConflicts(t *testing.T) {
	// A misconfigured deployment should learn about every conflict at once
	// rather than fixing them one agent restart at a time.
	in := validInputs()
	in.EnableIPSec = true
	in.EnableVTEP = true
	in.RoutingMode = option.RoutingModeNative

	err := Validate(in)
	require.Error(t, err)
	require.Contains(t, err.Error(), "IPsec")
	require.Contains(t, err.Error(), "VTEP")
	require.Contains(t, err.Error(), "--routing-mode=tunnel")
}
