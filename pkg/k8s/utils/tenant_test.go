// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
)

func TestSanitizePodLabelsInjectsTenant(t *testing.T) {
	ns := &FakeNamespace{Name: "acme-ns"}

	labels := SanitizePodLabels(map[string]string{"app": "web"}, ns, "", "default", "acme")
	require.Equal(t, "acme", labels[k8sconst.PolicyLabelTenant])
}

func TestSanitizePodLabelsOmitsTenantForDefaultVPC(t *testing.T) {
	ns := &FakeNamespace{Name: "plain-ns"}

	labels := SanitizePodLabels(map[string]string{"app": "web"}, ns, "", "default", "")
	assert.NotContains(t, labels, k8sconst.PolicyLabelTenant,
		"untenanted pods must keep the exact label set they have today")
}

func TestSanitizePodLabelsTenantCannotBeSpoofed(t *testing.T) {
	ns := &FakeNamespace{Name: "plain-ns"}

	// A pod that hand-sets the tenant label must not be able to claim
	// membership of another tenant, nor of any tenant at all.
	spoofed := map[string]string{k8sconst.PolicyLabelTenant: "globex"}

	labels := SanitizePodLabels(spoofed, ns, "", "default", "acme")
	assert.Equal(t, "acme", labels[k8sconst.PolicyLabelTenant])

	labels = SanitizePodLabels(spoofed, ns, "", "default", "")
	assert.NotContains(t, labels, k8sconst.PolicyLabelTenant)
}
