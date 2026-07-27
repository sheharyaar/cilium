// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tenancy

import (
	"github.com/spf13/pflag"
)

// EnableTenancy is the name of the flag gating overlapping-CIDR multi-tenancy.
const EnableTenancy = "enable-tenancy"

// Config is the user-facing configuration of the tenancy subsystem.
type Config struct {
	// EnableTenancy turns on overlapping-CIDR multi-tenancy. When unset the
	// agent behaves exactly as it does without this feature.
	EnableTenancy bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(EnableTenancy, def.EnableTenancy,
		"Enable overlapping-CIDR multi-tenancy: namespaces selected by a CiliumTenant form an isolated routing domain and may use pod CIDRs overlapping with other tenants (prototype)")
}

// DefaultConfig keeps tenancy off, so an agent that does not ask for it is
// unaffected.
var DefaultConfig = Config{
	EnableTenancy: false,
}
