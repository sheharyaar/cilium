// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilter

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
)

// The tenant label decides which numeric identity range an endpoint's identity
// is allocated from, so it must survive the default label filter. If it were
// filtered out, tenant endpoints would land in the cluster-local range and the
// datapath could not recover the tenant from the identity's high bits.
func TestTenantLabelSurvivesDefaultFilter(t *testing.T) {
	require.NoError(t, ParseLabelPrefixCfg(hivetest.Logger(t), nil, nil, ""))

	lbls := labels.Labels{
		k8sConst.PolicyLabelTenant: labels.NewLabel(k8sConst.PolicyLabelTenant, "acme", labels.LabelSourceK8s),
	}

	filtered, _ := Filter(lbls)
	require.Contains(t, filtered, k8sConst.PolicyLabelTenant)
	require.Equal(t, "acme", filtered[k8sConst.PolicyLabelTenant].Value)
}
