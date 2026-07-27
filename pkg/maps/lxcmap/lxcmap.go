// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

const (
	mapName = "cilium_lxc"

	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65535
)

// Map provides access to the endpoints (lxc) eBPF map.
type Map interface {
	// WriteEndpoint updates the BPF map with the endpoint information and links
	// the endpoint information to all keys provided.
	WriteEndpoint(f EndpointFrontend) error

	// SyncHostEntry checks if a host entry exists in the lxcmap and adds one if needed.
	// Returns boolean indicating if a new entry was added and an error.
	SyncHostEntry(addr netip.Addr) (bool, error)

	// DeleteEntry deletes a single map entry
	DeleteEntry(ea EndpointAddr) error

	// DeleteElement deletes the endpoint using all keys which represent the
	// endpoint. It returns the number of errors encountered during deletion.
	DeleteElement(logger *slog.Logger, f EndpointFrontend) []error

	// Dump returns the map (type map[string][]string) which contains all
	// data stored in BPF map.
	Dump(hash map[string][]string) error

	// DumpToMap dumps the contents of the lxcmap into a map and returns it,
	// keyed by address and tenant.
	DumpToMap() (map[EndpointAddr]EndpointInfo, error)
}

type lxcMap struct {
	bpfMap *bpf.Map
}

func newMap(registry *metrics.Registry) *lxcMap {
	return &lxcMap{
		bpfMap: bpf.NewMap(mapName,
			ebpf.Hash,
			&EndpointKey{},
			&EndpointInfo{},
			MaxEntries,
			0,
		).
			WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(mapName)),
	}
}

// OpenMap opens the pre-initialized LXC map for access.
// This should only be used from components which aren't capable of using hive - mainly the cilium-dbg.
// It needs to initialized beforehand via the Cilium Agent.
func OpenMap(logger *slog.Logger) (Map, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, mapName), &EndpointKey{}, &EndpointInfo{})
	if err != nil {
		return nil, fmt.Errorf("failed to open map: %w", err)
	}

	return &lxcMap{bpfMap: m}, nil
}

func (m *lxcMap) init() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *lxcMap) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}

const (
	// EndpointFlagHost indicates that this endpoint represents the host
	EndpointFlagHost = 1

	// EndpointFlagAtHostNS indicates that this endpoint is located at the host networking
	// namespace
	EndpointFlagAtHostNS = 2

	// EndpointFlagSkipMasqueradeV4 indicates that this endpoint should skip IPv4 masquerade for remote traffic
	EndpointFlagSkipMasqueradeV4 = 4

	// EndpointFlagSkipMasqueradeV6 indicates that this endpoint should skip IPv6 masquerade for remote traffic
	EndpointFlagSkipMasqueradeV6 = 8
)

// EndpointFrontend is the interface to implement for an object to synchronize
// with the endpoint BPF map.
type EndpointFrontend interface {
	LXCMac() mac.MAC
	GetNodeMAC() mac.MAC
	GetIfIndex() int
	GetParentIfIndex() int
	GetID() uint64
	IPv4Address() netip.Addr
	IPv6Address() netip.Addr
	GetIdentity() identity.NumericIdentity
	IsAtHostNS() bool
	// SkipMasqueradeV4 indicates whether this endpoint should skip IPv4 masquerade for remote traffic
	SkipMasqueradeV4() bool
	// SkipMasqueradeV6 indicates whether this endpoint should skip IPv6 masquerade for remote traffic
	SkipMasqueradeV6() bool
	// GetTenantID returns the tenant (VPC) the endpoint belongs to. 0 is the
	// default VPC.
	GetTenantID() uint16
}

// getBPFKeys returns all keys which should represent this endpoint in the BPF
// endpoints map.
//
// WriteEndpoint and DeleteElement both go through here, so the write and delete
// keys cannot drift apart. That matters because they are handed different
// objects: the regeneration snapshot on write and the Endpoint itself on delete.
// Both report the same tenant, since the tenant is immutable after endpoint
// creation and the snapshot copies it.
func (m *lxcMap) getBPFKeys(e EndpointFrontend) []*EndpointKey {
	tenantID := e.GetTenantID()

	keys := []*EndpointKey{}
	if e.IPv6Address().IsValid() {
		keys = append(keys, newEndpointKey(e.IPv6Address(), tenantID))
	}

	if e.IPv4Address().IsValid() {
		keys = append(keys, newEndpointKey(e.IPv4Address(), tenantID))
	}

	return keys
}

// getBPFValue returns the value which should represent this endpoint in the
// BPF endpoints map
// Must only be called if init() succeeded.
func (m *lxcMap) getBPFValue(e EndpointFrontend) (*EndpointInfo, error) {
	tmp := e.LXCMac()
	mac, err := tmp.Uint64()
	if len(tmp) > 0 && err != nil {
		return nil, fmt.Errorf("invalid LXC MAC: %w", err)
	}

	tmp = e.GetNodeMAC()
	nodeMAC, err := tmp.Uint64()
	if len(tmp) > 0 && err != nil {
		return nil, fmt.Errorf("invalid node MAC: %w", err)
	}

	// Both lxc and node mac can be nil for the case of L3/NOARP devices.
	info := &EndpointInfo{
		IfIndex:       uint32(e.GetIfIndex()),
		LxcID:         uint16(e.GetID()),
		MAC:           mac,
		NodeMAC:       nodeMAC,
		SecID:         e.GetIdentity().Uint32(), // Host byte-order
		ParentIfIndex: uint32(e.GetParentIfIndex()),
	}

	if e.IsAtHostNS() {
		info.Flags |= EndpointFlagAtHostNS
	}
	if e.SkipMasqueradeV4() {
		info.Flags |= EndpointFlagSkipMasqueradeV4
	}
	if e.SkipMasqueradeV6() {
		info.Flags |= EndpointFlagSkipMasqueradeV6
	}

	return info, nil
}

type pad2uint32 [2]uint32

// EndpointInfo represents the value of the endpoints BPF map.
//
// Must be in sync with struct endpoint_info in <bpf/lib/eps.h>
type EndpointInfo struct {
	IfIndex uint32 `align:"ifindex"`
	Unused  uint16 `align:"unused"`
	LxcID   uint16 `align:"lxc_id"`
	Flags   uint32 `align:"flags"`
	// go alignment
	_             uint32
	MAC           mac.Uint64MAC `align:"mac"`
	NodeMAC       mac.Uint64MAC `align:"node_mac"`
	SecID         uint32        `align:"sec_id"`
	ParentIfIndex uint32        `align:"parent_ifindex"`
	Pad           pad2uint32    `align:"pad"`
}

type EndpointKey struct {
	bpf.EndpointKey
}

// newEndpointKey returns an EndpointKey based on the provided IP address and
// tenant. The address family is automatically detected.
//
// The key's cluster ID field carries the tenant, which is what lets two tenants
// hold the same pod IP: the datapath looks the endpoint up as (IP, tenant)
// rather than by IP alone. Tenant 0 is the default VPC and yields exactly the
// key this produced before tenancy existed.
func newEndpointKey(addr netip.Addr, tenantID uint16) *EndpointKey {
	return &EndpointKey{
		EndpointKey: bpf.NewEndpointKey(addr, tenantID),
	}
}

// EndpointAddr identifies one entry in the endpoint map: an address within a
// tenant's routing domain.
//
// Dumping and deleting must be keyed on both, not on the address alone.
// Otherwise two tenants sharing a pod IP collapse into a single entry, and
// restore-time cleanup either deletes a live endpoint's entry or fails to
// notice a stale one.
type EndpointAddr struct {
	Addr     netip.Addr
	TenantID uint16
}

// NewEndpointAddr returns the endpoint map identity of an address in the default
// VPC.
func NewEndpointAddr(addr netip.Addr) EndpointAddr {
	return EndpointAddr{Addr: addr}
}

func (e EndpointAddr) String() string {
	if e.TenantID == 0 {
		return e.Addr.String()
	}
	return fmt.Sprintf("%s@%d", e.Addr, e.TenantID)
}

func (k *EndpointKey) New() bpf.MapKey { return &EndpointKey{} }

// IsHost returns true if the EndpointInfo represents a host IP
func (v *EndpointInfo) IsHost() bool {
	return v.Flags&EndpointFlagHost != 0
}

// String returns the human readable representation of an EndpointInfo
func (v *EndpointInfo) String() string {
	if v.Flags&EndpointFlagHost != 0 {
		return "(localhost)"
	}

	return fmt.Sprintf("id=%-5d sec_id=%-5d flags=0x%04X ifindex=%-3d mac=%s nodemac=%s parent_ifindex=%-3d",
		v.LxcID,
		v.SecID,
		v.Flags,
		v.IfIndex,
		v.MAC,
		v.NodeMAC,
		v.ParentIfIndex,
	)
}

func (v *EndpointInfo) New() bpf.MapValue { return &EndpointInfo{} }

func (m *lxcMap) WriteEndpoint(f EndpointFrontend) error {
	info, err := m.getBPFValue(f)
	if err != nil {
		return err
	}

	keys := m.getBPFKeys(f)
	var writtenKeys []*EndpointKey

	for _, key := range keys {
		if err := m.bpfMap.Update(key, info); err != nil {
			for _, k := range writtenKeys {
				_ = m.bpfMap.Delete(k)
			}
			return fmt.Errorf("failed to update key %v in LXC map: %w", key, err)
		}
		writtenKeys = append(writtenKeys, key)
	}

	return nil
}

// addHostEntry adds a special endpoint which represents the local host.
//
// Host IPs live in the default VPC: they are node addresses, not pod addresses,
// and are unique cluster-wide regardless of tenancy.
func (m *lxcMap) addHostEntry(addr netip.Addr) error {
	key := newEndpointKey(addr, 0)
	ep := &EndpointInfo{Flags: EndpointFlagHost}
	return m.bpfMap.Update(key, ep)
}

func (m *lxcMap) SyncHostEntry(addr netip.Addr) (bool, error) {
	key := newEndpointKey(addr, 0)
	value, err := m.bpfMap.Lookup(key)
	if err != nil || value.(*EndpointInfo).Flags&EndpointFlagHost == 0 {
		err = m.addHostEntry(addr)
		if err == nil {
			return true, nil
		}
	}
	return false, err
}

func (m *lxcMap) DeleteEntry(ea EndpointAddr) error {
	return m.bpfMap.Delete(newEndpointKey(ea.Addr, ea.TenantID))
}

func (m *lxcMap) DeleteElement(logger *slog.Logger, f EndpointFrontend) []error {
	var errors []error
	for _, k := range m.getBPFKeys(f) {
		if err := m.bpfMap.Delete(k); err != nil {
			errors = append(errors, fmt.Errorf("unable to delete key %v from %s: %w", k, bpf.MapPath(logger, mapName), err))
		}
	}

	return errors
}

func (m *lxcMap) Dump(hash map[string][]string) error {
	return m.bpfMap.Dump(hash)
}

func (m *lxcMap) DumpToMap() (map[EndpointAddr]EndpointInfo, error) {
	result := map[EndpointAddr]EndpointInfo{}
	callback := func(key bpf.MapKey, value bpf.MapValue) {
		if info, ok := value.(*EndpointInfo); ok {
			if endpointKey, ok := key.(*EndpointKey); ok {
				result[EndpointAddr{
					Addr:     endpointKey.ToAddr(),
					TenantID: endpointKey.ClusterID,
				}] = *info
			}
		}
	}

	if err := m.bpfMap.DumpWithCallback(callback); err != nil {
		return nil, fmt.Errorf("unable to read BPF endpoint list: %w", err)
	}

	return result, nil
}
