// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"log/slog"
	"net"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
)

// gatewayIPCache is the part of ipcache.IPCache the gateway reconciler uses.
// Narrowing it keeps the reconciler testable without a real ipcache.
type gatewayIPCache interface {
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata,
		newIdentity ipcache.Identity) (bool, error)
	Delete(IP string, source source.Source) bool
}

// gatewaySpec is a tenant's egress gateway selection.
type gatewaySpec struct {
	namespace string
	selector  slim_labels.Selector
}

// gatewayCandidate is an endpoint that might be some tenant's gateway. It is
// built from a CiliumEndpoint, which the agent sees cluster-wide and which
// already carries everything the ipcache entry needs.
type gatewayCandidate struct {
	namespace string
	name      string
	labels    map[string]string
	podIP     string
	nodeIP    string
	identity  uint32
}

func (c gatewayCandidate) key() string { return c.namespace + "/" + c.name }

type tenantEntry struct {
	id      uint16
	gateway *gatewaySpec
	// installed is the gateway currently backing this tenant's default route,
	// empty when none is.
	installed string
}

// tenantGateways keeps each tenant's default route pointing at its egress
// gateway pod.
//
// A tenant's pod IPs only resolve inside its own tenant, so anything else is
// unroutable. Installing "0.0.0.0/0@<tenantID>" gives the tenant a least
// specific ipcache entry that LPM falls back to, which redirects otherwise
// unresolvable destinations to the gateway pod. Traffic is tunnelled to the
// node the gateway runs on and carries the gateway's identity, so from the rest
// of the datapath's point of view the gateway is the destination.
//
// Both tenants and endpoints arrive as events in no guaranteed order, so both
// sides are kept and the route is recomputed whenever either changes.
type tenantGateways struct {
	logger  *slog.Logger
	ipcache gatewayIPCache

	mu lock.Mutex
	// tenants by CiliumTenant name.
	tenants map[string]*tenantEntry
	// candidates by "namespace/name".
	candidates map[string]gatewayCandidate
}

func newTenantGateways(logger *slog.Logger, ipc gatewayIPCache) *tenantGateways {
	return &tenantGateways{
		logger:     logger,
		ipcache:    ipc,
		tenants:    make(map[string]*tenantEntry),
		candidates: make(map[string]gatewayCandidate),
	}
}

// parseGatewaySpec compiles a tenant's egress gateway selection. A nil result
// means the tenant has no gateway.
func parseGatewaySpec(tenantName, namespace string, sel *slim_metav1.LabelSelector) (*gatewaySpec, error) {
	if sel == nil || namespace == "" {
		return nil, nil
	}

	compiled, err := slim_metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return nil, fmt.Errorf("tenant %q: compiling egressGateway podSelector: %w", tenantName, err)
	}
	return &gatewaySpec{namespace: namespace, selector: compiled}, nil
}

func (g *tenantGateways) upsertTenant(name string, id uint16, spec *gatewaySpec) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.tenants[name]
	if !ok {
		entry = &tenantEntry{}
		g.tenants[name] = entry
	}
	entry.id = id
	entry.gateway = spec

	return g.reconcileLocked(name, entry)
}

func (g *tenantGateways) deleteTenant(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.tenants[name]
	if !ok {
		return
	}
	g.withdrawLocked(entry)
	delete(g.tenants, name)
}

func (g *tenantGateways) upsertEndpoint(c gatewayCandidate) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.candidates[c.key()] = c
	return g.reconcileAllLocked()
}

func (g *tenantGateways) deleteEndpoint(namespace, name string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	delete(g.candidates, namespace+"/"+name)
	return g.reconcileAllLocked()
}

func (g *tenantGateways) reconcileAllLocked() error {
	var errs error
	for name, entry := range g.tenants {
		if err := g.reconcileLocked(name, entry); err != nil {
			errs = err
		}
	}
	return errs
}

// reconcileLocked brings one tenant's default route in line with the current
// set of candidates.
func (g *tenantGateways) reconcileLocked(name string, entry *tenantEntry) error {
	// Tenant ID 0 would install 0.0.0.0/0 in the default VPC and hijack every
	// untenanted endpoint's fallback route.
	if entry.gateway == nil || entry.id == 0 {
		g.withdrawLocked(entry)
		return nil
	}

	gw, found := g.matchLocked(entry.gateway)
	if !found {
		g.withdrawLocked(entry)
		return nil
	}

	nodeIP := net.ParseIP(gw.nodeIP)
	if nodeIP == nil {
		g.withdrawLocked(entry)
		return fmt.Errorf("tenant %q: gateway %s has no usable node IP %q",
			name, gw.key(), gw.nodeIP)
	}

	key := defaultRouteKey(entry.id)
	if _, err := g.ipcache.Upsert(key, nodeIP, 0, nil, ipcache.Identity{
		ID:     identity.NumericIdentity(gw.identity),
		Source: source.Generated,
	}); err != nil {
		return fmt.Errorf("tenant %q: installing default route via %s: %w",
			name, gw.key(), err)
	}

	if entry.installed != gw.key() {
		g.logger.Info("Installed tenant default route via egress gateway",
			logfields.Tenant, name,
			logfields.TenantID, entry.id,
			"gateway", gw.key(),
			logfields.IPAddr, gw.podIP,
		)
	}
	entry.installed = gw.key()
	return nil
}

func (g *tenantGateways) withdrawLocked(entry *tenantEntry) {
	if entry.installed == "" || entry.id == 0 {
		return
	}

	g.ipcache.Delete(defaultRouteKey(entry.id), source.Generated)
	g.logger.Info("Withdrew tenant default route",
		logfields.TenantID, entry.id,
		"gateway", entry.installed,
	)
	entry.installed = ""
}

// matchLocked finds the endpoint a gateway spec selects. Ties are broken by the
// lowest key so the choice does not depend on map iteration order.
func (g *tenantGateways) matchLocked(spec *gatewaySpec) (gatewayCandidate, bool) {
	var (
		best  gatewayCandidate
		found bool
	)
	for _, c := range g.candidates {
		if c.namespace != spec.namespace || c.podIP == "" {
			continue
		}
		if !spec.selector.Matches(slim_labels.Set(c.labels)) {
			continue
		}
		if !found || c.key() < best.key() {
			best, found = c, true
		}
	}
	return best, found
}

// defaultRouteKey is the tenant-scoped least specific ipcache key.
func defaultRouteKey(tenantID uint16) string {
	return cmtypes.AnnotateIPCacheKeyWithClusterID("0.0.0.0/0", uint32(tenantID))
}
