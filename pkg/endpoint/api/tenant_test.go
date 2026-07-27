// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// stubResolver is a tenancy.Resolver that answers from a fixed map.
type stubResolver struct {
	enabled bool
	ids     map[string]uint16
	names   map[string]string
}

func (s stubResolver) Enabled() bool { return s.enabled }

func (s stubResolver) TenantIDForNamespace(ns string) uint16 { return s.ids[ns] }

func (s stubResolver) TenantNameForNamespace(ns string) string { return s.names[ns] }

func TestResolveTenantID(t *testing.T) {
	for _, tc := range []struct {
		name      string
		manager   endpointAPIManager
		namespace string
		want      uint16
	}{
		{
			name:      "no resolver in the graph",
			manager:   endpointAPIManager{},
			namespace: "acme-ns",
			want:      0,
		},
		{
			name: "resolver disabled",
			manager: endpointAPIManager{tenancy: stubResolver{
				enabled: false,
				ids:     map[string]uint16{"acme-ns": 3},
			}},
			namespace: "acme-ns",
			want:      0,
		},
		{
			name: "empty namespace",
			manager: endpointAPIManager{tenancy: stubResolver{
				enabled: true,
				ids:     map[string]uint16{"": 3},
			}},
			namespace: "",
			want:      0,
		},
		{
			name: "untenanted namespace",
			manager: endpointAPIManager{tenancy: stubResolver{
				enabled: true,
				ids:     map[string]uint16{"acme-ns": 3},
			}},
			namespace: "other-ns",
			want:      0,
		},
		{
			name: "tenant namespace",
			manager: endpointAPIManager{tenancy: stubResolver{
				enabled: true,
				ids:     map[string]uint16{"acme-ns": 3},
			}},
			namespace: "acme-ns",
			want:      3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.manager.resolveTenantID(tc.namespace))
		})
	}
}
