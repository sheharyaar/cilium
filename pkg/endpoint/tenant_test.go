// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
)

func TestTenantIDRoundTripsThroughRestoreState(t *testing.T) {
	in := &serializableEndpoint{ID: 512, TenantID: 42}

	raw, err := json.Marshal(in)
	require.NoError(t, err)

	var out serializableEndpoint
	require.NoError(t, json.Unmarshal(raw, &out))
	require.Equal(t, uint16(42), out.TenantID)

	ep := &Endpoint{}
	ep.fromSerializedEndpoint(&out)
	require.Equal(t, uint16(42), ep.TenantID)
	require.Equal(t, uint16(42), ep.GetTenantID())
}

func TestTenantIDOmittedWhenDefaultVPC(t *testing.T) {
	// Restore state for an untenanted endpoint, and all state written by an
	// agent without tenancy, must not carry the field at all.
	raw, err := json.Marshal(&serializableEndpoint{ID: 513})
	require.NoError(t, err)

	var generic map[string]any
	require.NoError(t, json.Unmarshal(raw, &generic))
	require.NotContains(t, generic, "tenantID")

	// Restore state predating this field restores as the default VPC.
	var out serializableEndpoint
	require.NoError(t, json.Unmarshal([]byte(`{"ID":513}`), &out))

	ep := &Endpoint{}
	ep.fromSerializedEndpoint(&out)
	require.Equal(t, uint16(0), ep.GetTenantID())
}

func TestTenantIDSerializedFromEndpoint(t *testing.T) {
	ep := &Endpoint{TenantID: 7}
	require.Equal(t, uint16(7), ep.toSerializedEndpoint().TenantID)
}

func TestTenantIDInEpInfoCache(t *testing.T) {
	s := setupEndpointSuite(t)
	ep := s.endpointCreator(t, 514, identity.NumericIdentity(1514))
	ep.TenantID = 7

	cache := ep.createEpInfoCache("")
	require.NotNil(t, cache)
	require.Equal(t, uint16(7), cache.GetTenantID())
}
