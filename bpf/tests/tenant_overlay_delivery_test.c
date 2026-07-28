// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Cross-node pod-to-pod delivery inside a tenant.
 *
 * Two endpoints on this node share a pod IP and differ only by tenant, which is
 * the situation overlapping-CIDR multi-tenancy exists to support. A packet
 * arrives from the tunnel addressed to that IP; the only thing distinguishing
 * the two possible destinations is the tenant encoded in the high bits of the
 * security identity the tunnel carries.
 *
 * The decap path must therefore look the endpoint up as (IP, tenant). If it
 * looks up by IP alone it either finds the wrong endpoint or, once the endpoint
 * map is tenant-keyed, finds nothing at all and cross-node traffic inside a
 * tenant stops working.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include "mock_skb_metadata.h"

#define ENCAP_IFINDEX 1

/* Tenancy is IPv4 and tunnel only. */
#define ENABLE_IPV4
#define TUNNEL_MODE

/* This is the flag the agent emits for --enable-tenancy, and what compiles in
 * the cluster ID dimension that the tenant reuses.
 */
#define ENABLE_CLUSTER_AWARE_ADDRESSING
/* Tenancy-specific: tells the decap path the ID in an identity is a tenant,
 * not a remote ClusterMesh cluster.
 */
#define ENABLE_TENANCY

#include <bpf/config/node.h>

#define POD_IP			v4_pod_one
#define CLIENT_NODE_IP		v4_ext_one

/* Same pod IP, two tenants, two different interfaces. */
#define TENANT_ONE		1
#define TENANT_TWO		2
#define TENANT_ONE_IFINDEX	111
#define TENANT_TWO_IFINDEX	222

#define TENANT_ONE_MAC		mac_one
#define TENANT_TWO_MAC		mac_three
#define NODE_MAC		mac_two
#define CLIENT_ROUTER_MAC	mac_four

/* Identities carry the tenant in the bits above IDENTITY_LEN, which is how the
 * decap path recovers it.
 */
#define TENANT_ONE_IDENTITY	((TENANT_ONE << 16) | 0xff01)
#define TENANT_TWO_IDENTITY	((TENANT_TWO << 16) | 0xff02)

#define SRC_PORT		tcp_src_one
#define DST_PORT		tcp_svc_one

/* Mock the tunnel key so the packet looks like it came from the overlay. */
#define skb_get_tunnel_key mock_skb_get_tunnel_key

static __u32 mock_tunnel_identity = TENANT_ONE_IDENTITY;

int mock_skb_get_tunnel_key(struct __ctx_buff *ctx __maybe_unused, struct bpf_tunnel_key *to,
			    __u32 size __maybe_unused, __u32 flags __maybe_unused)
{
	to->remote_ipv4 = CLIENT_NODE_IP;
	to->tunnel_id = mock_tunnel_identity;
	return 0;
}

#define DEBUG
#include <lib/drop.h>

#define _send_drop_notify mock_send_drop_notify

static __always_inline
int mock_send_drop_notify(__u8 file __maybe_unused, __u16 line __maybe_unused,
			  struct __ctx_buff *ctx, __u32 src __maybe_unused,
			  __u32 dst __maybe_unused, __u32 dst_id __maybe_unused,
			  __u32 reason, __u32 exitcode, enum metric_dir direction)
{
	cilium_dbg3(ctx, DBG_GENERIC, reason, exitcode, direction);
	return exitcode;
}

#include "lib/bpf_overlay.h"

/* The local node is not a ClusterMesh member; tenants are the only users of the
 * cluster ID dimension here.
 */
ASSIGN_CONFIG(__u32, cluster_id, 0)

#include "lib/endpoint.h"
#include "lib/ipcache.h"

static __always_inline int
pktgen_from_overlay(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)CLIENT_ROUTER_MAC,
					  (__u8 *)NODE_MAC,
					  CLIENT_NODE_IP, POD_IP,
					  SRC_PORT, DST_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = 0;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

/* Register both same-IP endpoints. Order is deliberate: tenant two is inserted
 * last, so a tenant-blind lookup keyed on IP alone would tend to find it.
 */
static __always_inline void add_both_tenants(void)
{
	endpoint_v4_add_entry_cluster(POD_IP, TENANT_ONE, TENANT_ONE_IFINDEX, 0, 0,
				      TENANT_ONE_IDENTITY, 0,
				      (__u8 *)TENANT_ONE_MAC, (__u8 *)NODE_MAC);
	endpoint_v4_add_entry_cluster(POD_IP, TENANT_TWO, TENANT_TWO_IFINDEX, 0, 0,
				      TENANT_TWO_IDENTITY, 0,
				      (__u8 *)TENANT_TWO_MAC, (__u8 *)NODE_MAC);
}

/* 01: a packet whose identity says tenant one must reach tenant one's endpoint,
 * not the identically addressed endpoint in tenant two.
 */
PKTGEN("tc", "01_overlay_delivers_to_tenant_one")
int overlay_tenant_one_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_overlay(ctx);
}

SETUP("tc", "01_overlay_delivers_to_tenant_one")
int overlay_tenant_one_setup(struct __ctx_buff *ctx)
{
	mock_tunnel_identity = TENANT_ONE_IDENTITY;
	add_both_tenants();

	return overlay_receive_packet(ctx);
}

CHECK("tc", "01_overlay_delivers_to_tenant_one")
int overlay_tenant_one_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Delivery tail-calls into the policy program, which is empty in this
	 * harness, so the packet is dropped there. Reaching that point at all
	 * means an endpoint was found and local delivery ran.
	 */
	if (*status_code != CTX_ACT_DROP)
		test_fatal("unexpected status code %d", *status_code);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	/* The rewritten destination MAC is what identifies which of the two
	 * same-IP endpoints was selected.
	 */
	if (memcmp(l2->h_dest, (__u8 *)TENANT_ONE_MAC, ETH_ALEN) != 0)
		test_fatal("delivered to the wrong tenant's endpoint");

	test_finish();
}

/* 02: the same packet, but the identity says tenant two. Same destination IP,
 * different endpoint. This is the pair that a tenant-blind lookup cannot get
 * right for both cases.
 */
PKTGEN("tc", "02_overlay_delivers_to_tenant_two")
int overlay_tenant_two_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_overlay(ctx);
}

SETUP("tc", "02_overlay_delivers_to_tenant_two")
int overlay_tenant_two_setup(struct __ctx_buff *ctx)
{
	mock_tunnel_identity = TENANT_TWO_IDENTITY;
	add_both_tenants();

	return overlay_receive_packet(ctx);
}

CHECK("tc", "02_overlay_delivers_to_tenant_two")
int overlay_tenant_two_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_DROP)
		test_fatal("unexpected status code %d", *status_code);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (memcmp(l2->h_dest, (__u8 *)TENANT_TWO_MAC, ETH_ALEN) != 0)
		test_fatal("delivered to the wrong tenant's endpoint");

	test_finish();
}

/* 03: an identity for a tenant that has no endpoint at this address must not
 * fall through to some other tenant's endpoint. The packet goes to the host
 * instead, which is what "no local endpoint" means on this path.
 */
PKTGEN("tc", "03_overlay_no_cross_tenant_fallback")
int overlay_no_fallback_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_overlay(ctx);
}

SETUP("tc", "03_overlay_no_cross_tenant_fallback")
int overlay_no_fallback_setup(struct __ctx_buff *ctx)
{
	/* Only tenant two holds this IP, but the packet claims tenant one. */
	endpoint_v4_del_entry(POD_IP);
	endpoint_v4_add_entry_cluster(POD_IP, TENANT_TWO, TENANT_TWO_IFINDEX, 0, 0,
				      TENANT_TWO_IDENTITY, 0,
				      (__u8 *)TENANT_TWO_MAC, (__u8 *)NODE_MAC);

	mock_tunnel_identity = TENANT_ONE_IDENTITY;

	return overlay_receive_packet(ctx);
}

CHECK("tc", "03_overlay_no_cross_tenant_fallback")
int overlay_no_fallback_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	/* The decisive assertion: tenant two's endpoint must not have been
	 * selected for a tenant one packet.
	 */
	if (memcmp(l2->h_dest, (__u8 *)TENANT_TWO_MAC, ETH_ALEN) == 0)
		test_fatal("packet leaked across tenants");

	test_finish();
}
