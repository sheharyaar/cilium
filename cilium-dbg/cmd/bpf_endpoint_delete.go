// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
)

var bpfEndpointDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete local endpoint entries",
	Long: `Delete a local endpoint entry.

The endpoint is identified by its IP address. With multi-tenancy enabled the same
IP may exist in several tenants, so the entry can be scoped to one of them by
appending "@<tenantID>", for example 10.10.0.5@3. Without a tenant the entry in
the default VPC is deleted.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf endpoint delete")

		if args[0] == "" {
			Fatalf("Please specify the endpoint to delete")
		}

		ea, err := parseEndpointAddr(args[0])
		if err != nil {
			Fatalf("Unable to parse endpoint '%s': %v", args[0], err)
		}

		m, err := lxcmap.OpenMap(log)
		if err != nil {
			Fatalf("Unable to open map: %s", err)
		}

		if err := m.DeleteEntry(ea); err != nil {
			Fatalf("Unable to delete endpoint entry: %s", err)
		}
	},
}

// parseEndpointAddr parses an endpoint map address, either a bare IP or
// "<ip>@<tenantID>".
func parseEndpointAddr(arg string) (lxcmap.EndpointAddr, error) {
	ipStr, tenantStr, hasTenant := strings.Cut(arg, "@")

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return lxcmap.EndpointAddr{}, fmt.Errorf("invalid IP %q: %w", ipStr, err)
	}

	if !hasTenant {
		return lxcmap.NewEndpointAddr(addr), nil
	}

	tenantID, err := strconv.ParseUint(tenantStr, 10, 16)
	if err != nil {
		return lxcmap.EndpointAddr{}, fmt.Errorf("invalid tenant ID %q: %w", tenantStr, err)
	}

	return lxcmap.EndpointAddr{Addr: addr, TenantID: uint16(tenantID)}, nil
}

func init() {
	BPFEndpointCmd.AddCommand(bpfEndpointDeleteCmd)
}
