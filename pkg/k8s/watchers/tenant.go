// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/tenancy"
)

// tenantIPCacheKey returns the ipcache key for a pod IP in a namespace.
//
// A tenant's pod IP is annotated as "<ip>@<tenantID>", the same form the
// ClusterMesh watcher uses for remote clusters, which is how two tenants can
// hold the same IP in the ipcache without one shadowing the other. Pods in the
// default VPC keep a bare IP, so the untenanted ipcache is byte-identical to
// what it was before tenancy existed.
//
// Every upsert and every delete of a pod IP must go through this function.
// Deriving the two keys differently would leave a stale ipcache entry behind on
// pod deletion, which keeps resolving traffic to an identity that no longer
// exists.
func tenantIPCacheKey(resolver tenancy.Resolver, namespace, ip string) string {
	// A CiliumEndpoint's address pair carries an empty string for a missing
	// address family; annotating that would produce a meaningless key.
	if ip == "" {
		return ip
	}
	if resolver == nil || !resolver.Enabled() {
		return ip
	}

	tenantID := resolver.TenantIDForNamespace(namespace)
	if tenantID == 0 {
		return ip
	}

	return cmtypes.AnnotateIPCacheKeyWithClusterID(ip, uint32(tenantID))
}
