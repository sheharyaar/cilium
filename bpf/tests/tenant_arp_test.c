// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* ARP is unaffected by tenancy, and this test exists to keep it that way.
 *
 * A pod only ever ARPs for its gateway: the CNI gives it a /32 address and a
 * link route to the gateway, so no peer is ever on-link. The veth pair is
 * point-to-point, so an ARP frame from a tenant pod reaches nothing but its own
 * endpoint program, and that program answers every target address except the
 * endpoint's own with the interface MAC. There is no map lookup on this path and
 * therefore nothing to scope to a tenant.
 *
 * That means duplicate pod IPs across tenants can never collide in ARP, and it
 * also means a future change that made the ARP responder consult the endpoint or
 * ipcache maps would be introducing a tenant leak. These assertions are the
 * tripwire for that.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define TUNNEL_MODE
#define ENCAP_IFINDEX 1

#define ENABLE_ARP_RESPONDER
#define ENABLE_CLUSTER_AWARE_ADDRESSING
/* Tenancy-specific: tells the decap path the ID in an identity is a tenant,
 * not a remote ClusterMesh cluster.
 */
#define ENABLE_TENANCY

#include <bpf/config/node.h>

#define TENANT_ONE		1

#define POD_IP			v4_pod_one
/* The address the pod ARPs for. Its value does not matter to the responder,
 * which is the point.
 */
#define GATEWAY_IP		v4_svc_one

#define POD_MAC			mac_one
#define IFACE_MAC		mac_two

#define POD_IDENTITY		((TENANT_ONE << 16) | 0xff01)

#undef EVENT_SOURCE

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(__u32, cluster_id, 0)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = POD_IP })
ASSIGN_CONFIG(__u32, security_label, POD_IDENTITY)
/* The endpoint is in a tenant. Nothing on the ARP path may depend on this. */
ASSIGN_CONFIG(__u32, tenant_id, TENANT_ONE)

#include "lib/endpoint.h"

static __always_inline int
pktgen_arp_request(struct __ctx_buff *ctx, __be32 target)
{
	struct pktgen builder;
	struct arphdreth *arp;
	struct ethhdr *l2;

	pktgen__init(&builder, ctx);

	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	/* A real ARP request is broadcast, which is what arp_check() accepts
	 * alongside the interface's own MAC.
	 */
	memcpy(l2->h_source, (__u8 *)POD_MAC, ETH_ALEN);
	memset(l2->h_dest, 0xff, ETH_ALEN);
	l2->h_proto = bpf_htons(ETH_P_ARP);

	arp = pktgen__push_default_arphdr_ethernet(&builder);
	if (!arp)
		return TEST_ERROR;

	arp->ar_op = bpf_htons(ARPOP_REQUEST);
	memcpy(arp->ar_sha, (__u8 *)POD_MAC, ETH_ALEN);
	arp->ar_sip = POD_IP;
	memset(arp->ar_tha, 0, ETH_ALEN);
	arp->ar_tip = target;

	pktgen__finish(&builder);
	return 0;
}

/* 01: a tenant pod's ARP request for its gateway is answered locally, with the
 * interface MAC, exactly as it would be without tenancy.
 */
PKTGEN("tc", "01_tenant_pod_arp_is_answered")
int tenant_arp_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_arp_request(ctx, GATEWAY_IP);
}

SETUP("tc", "01_tenant_pod_arp_is_answered")
int tenant_arp_setup(struct __ctx_buff *ctx)
{
	/* Deliberately no endpoint or ipcache entries. The responder must not
	 * need them; if this test ever starts depending on them, the ARP path has
	 * grown a map lookup that would need tenant scoping.
	 */
	return pod_send_packet(ctx);
}

CHECK("tc", "01_tenant_pod_arp_is_answered")
int tenant_arp_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct arphdreth *arp;
	__s32 *status_code;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* The reply is sent straight back out of the interface it arrived on. */
	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("ARP request was not answered, status %d", *status_code);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (l2->h_proto != bpf_htons(ETH_P_ARP))
		test_fatal("reply is not ARP");

	arp = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)arp + sizeof(struct arphdreth) > data_end)
		test_fatal("arp header out of bounds");

	if (arp->ar_op != bpf_htons(ARPOP_REPLY))
		test_fatal("not an ARP reply");

	/* The reply is for the address that was asked about, and carries no
	 * tenant information at all.
	 */
	if (arp->ar_sip != GATEWAY_IP)
		test_fatal("reply is for the wrong address");

	test_finish();
}

/* 02: the responder still refuses to answer for the endpoint's own address, so
 * duplicate address detection inside the pod keeps working. Tenancy makes this
 * more relevant, not less: the same address genuinely exists elsewhere on the
 * node, in another tenant, and must not be advertised here.
 */
PKTGEN("tc", "02_own_address_is_not_answered")
int own_addr_arp_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_arp_request(ctx, POD_IP);
}

SETUP("tc", "02_own_address_is_not_answered")
int own_addr_arp_setup(struct __ctx_buff *ctx)
{
	/* Give the same address to another tenant, which is legal. The responder
	 * must still stay silent rather than answering on that endpoint's behalf.
	 */
	endpoint_v4_add_entry_cluster(POD_IP, TENANT_ONE + 1, 222, 0, 0,
				      ((TENANT_ONE + 1) << 16) | 0xff02, 0,
				      (__u8 *)POD_MAC, (__u8 *)IFACE_MAC);

	return pod_send_packet(ctx);
}

CHECK("tc", "02_own_address_is_not_answered")
int own_addr_arp_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Passed to the stack unanswered. */
	if (*status_code != CTX_ACT_OK)
		test_fatal("expected the request to be passed to the stack, status %d",
			   *status_code);

	test_finish();
}
