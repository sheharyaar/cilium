// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumtenant",path="ciliumtenants",scope="Cluster",shortName={ctn}
// +kubebuilder:printcolumn:JSONPath=".status.tenantID",name="TenantID",type=integer
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumTenant defines an isolated routing domain (VPC) whose namespaces may
// use pod CIDRs that overlap with the pod CIDRs of other tenants.
//
// A tenant is realized in the datapath by reusing the ClusterMesh cluster ID
// dimension: every endpoint in a tenant namespace carries the tenant ID in the
// ipcache key, the endpoint map key, the security identity high bits and the
// per-tenant conntrack and NAT map selection. Tenant ID 0 is the default VPC
// and behaves exactly as a cluster without tenancy enabled.
type CiliumTenant struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired configuration of the tenant.
	//
	// +kubebuilder:validation:Required
	Spec TenantSpec `json:"spec"`

	// Status is the running status of the tenant, maintained by the operator.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status TenantStatus `json:"status,omitempty"`
}

type TenantSpec struct {
	// NamespaceSelector selects the namespaces belonging to this tenant. Every
	// endpoint created in a selected namespace is placed in this tenant's
	// routing domain.
	//
	// A namespace must not be selected by more than one CiliumTenant. If it is,
	// the tenant with the numerically lowest allocated tenant ID wins and the
	// remaining tenants report a TenantConflict condition.
	//
	// +kubebuilder:validation:Required
	NamespaceSelector *slimv1.LabelSelector `json:"namespaceSelector"`

	// EgressGateway optionally selects the tenant's egress NAT gateway pod. The
	// gateway pod becomes the tenant's default route: destinations that do not
	// resolve inside the tenant are redirected to it.
	//
	// +kubebuilder:validation:Optional
	EgressGateway *TenantEgressGateway `json:"egressGateway,omitempty"`
}

type TenantEgressGateway struct {
	// PodSelector selects the gateway pod inside the tenant.
	//
	// +kubebuilder:validation:Required
	PodSelector *slimv1.LabelSelector `json:"podSelector"`

	// Namespace is the namespace the gateway pod lives in. It must be a
	// namespace belonging to this tenant.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

type TenantStatus struct {
	// TenantID is the datapath identifier allocated by the operator. 0 means no
	// ID has been allocated yet.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=255
	TenantID uint32 `json:"tenantID,omitempty"`

	// Conditions is the current set of conditions of the tenant.
	//
	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// +deepequal-gen=false
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Conditions reported on CiliumTenant.Status.
const (
	// TenantConditionIDAllocated reports whether the operator managed to
	// allocate a datapath tenant ID for this tenant.
	TenantConditionIDAllocated = "cilium.io/TenantIDAllocated"

	// TenantConditionConflict reports that a namespace selected by this tenant
	// is also selected by another tenant.
	TenantConditionConflict = "cilium.io/TenantConflict"
)

// Reasons used with the CiliumTenant conditions above.
const (
	// TenantReasonAllocated is the reason used when a tenant ID was allocated.
	TenantReasonAllocated = "Allocated"

	// TenantReasonExhausted is the reason used when no tenant ID is available.
	TenantReasonExhausted = "Exhausted"

	// TenantReasonNamespaceConflict is the reason used when a namespace is
	// claimed by more than one tenant.
	TenantReasonNamespaceConflict = "NamespaceConflict"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// CiliumTenantList is a list of CiliumTenant objects.
type CiliumTenantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// Items is a list of CiliumTenants.
	Items []CiliumTenant `json:"items"`
}
