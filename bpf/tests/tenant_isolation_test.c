// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Structural isolation between tenants on the egress path.
 *
 * A pod in one tenant sends to an address that exists in both tenants' ipcache
 * slices with different identities, and to an address that exists only in the
 * other tenant. The sending endpoint's own tenant is what decides which slice is
 * consulted, so:
 *
 *   - the same destination IP resolves to this tenant's identity, not the other
 *     tenant's, and
 *   - an address that only exists in another tenant does not resolve at all, so
 *     the packet is dropped rather than delivered across the tenant boundary.
 *
 * The second case is the isolation guarantee: nothing denies the traffic, there
 * is simply no route to it.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define TUNNEL_MODE
#define ENCAP_IFINDEX 1

#define ENABLE_CLUSTER_AWARE_ADDRESSING
/* Tenancy-specific: tells the decap path the ID in an identity is a tenant,
 * not a remote ClusterMesh cluster.
 */
#define ENABLE_TENANCY

#include <bpf/config/node.h>

#define SENDER_TENANT		1
#define OTHER_TENANT		2

#define SENDER_IP		v4_pod_one
#define SENDER_PORT		tcp_src_one

/* Present in both tenants, with a different identity in each. */
#define SHARED_IP		v4_pod_two
/* Present only in the other tenant. */
#define OTHER_ONLY_IP		v4_pod_three
#define DST_PORT		tcp_svc_one

#define SENDER_IDENTITY		((SENDER_TENANT << 16) | 0xff01)
#define SHARED_IP_MINE		((SENDER_TENANT << 16) | 0xff02)
#define SHARED_IP_THEIRS	((OTHER_TENANT << 16) | 0xff03)
#define OTHER_ONLY_IDENTITY	((OTHER_TENANT << 16) | 0xff04)

#define REMOTE_NODE_IP		v4_ext_one

#define SENDER_MAC		mac_one
#define NODE_MAC		mac_two

/* EVENT_SOURCE is defined by both common.h and bpf_lxc.c. */
#undef EVENT_SOURCE

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(__u32, cluster_id, 0)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = SENDER_IP })
ASSIGN_CONFIG(__u32, security_label, SENDER_IDENTITY)
/* The sending endpoint belongs to tenant one. This is the value the agent
 * writes per endpoint, and what scopes every lookup below.
 */
ASSIGN_CONFIG(__u32, tenant_id, SENDER_TENANT)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/policy.h"

static __always_inline int
pktgen_to(struct __ctx_buff *ctx, __be32 daddr)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SENDER_MAC,
					  (__u8 *)NODE_MAC,
					  SENDER_IP, daddr,
					  SENDER_PORT, DST_PORT);
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

/* Populate both tenants' view of the world. SHARED_IP exists in both with
 * different identities; OTHER_ONLY_IP exists only in the other tenant.
 */
static __always_inline void populate_ipcache(void)
{
	ipcache_v4_add_entry(SHARED_IP, SENDER_TENANT, SHARED_IP_MINE,
			     REMOTE_NODE_IP, 0);
	ipcache_v4_add_entry(SHARED_IP, OTHER_TENANT, SHARED_IP_THEIRS,
			     REMOTE_NODE_IP, 0);
	ipcache_v4_add_entry(OTHER_ONLY_IP, OTHER_TENANT, OTHER_ONLY_IDENTITY,
			     REMOTE_NODE_IP, 0);
}

/* 01: the shared address resolves inside the sender's own tenant. The proof is
 * the identity carried to the tunnel: it must be this tenant's, even though the
 * other tenant holds the same address.
 */
PKTGEN("tc", "01_shared_ip_resolves_in_own_tenant")
int shared_ip_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to(ctx, SHARED_IP);
}

SETUP("tc", "01_shared_ip_resolves_in_own_tenant")
int shared_ip_setup(struct __ctx_buff *ctx)
{
	populate_ipcache();
	endpoint_v4_add_entry_cluster(SENDER_IP, SENDER_TENANT, 0, 0, 0,
				      SENDER_IDENTITY, 0, NULL, NULL);

	/* Allow only the identity this tenant's ipcache slice holds for the
	 * shared address. If the lookup resolved in the other tenant's slice, or
	 * missed and fell back to world, policy denies and the packet is
	 * dropped, which is what the check below distinguishes.
	 */
	policy_add_egress_allow_l3_l4_entry(SHARED_IP_MINE, IPPROTO_TCP,
					    DST_PORT, 0);

	return pod_send_packet(ctx);
}

CHECK("tc", "01_shared_ip_resolves_in_own_tenant")
int shared_ip_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	/* Only this tenant's identity for the shared address is allowed, so
	 * getting past policy is the proof that the lookup used this tenant's
	 * ipcache slice.
	 */
	if (*status_code == CTX_ACT_DROP)
		test_fatal("shared IP did not resolve to this tenant's identity");

	test_finish();
}

/* 02: an address that exists only in another tenant does not resolve, and the
 * packet is dropped as unroutable. This is the isolation guarantee, and it is
 * structural: no policy rule is involved.
 */
PKTGEN("tc", "02_cross_tenant_address_is_unroutable")
int cross_tenant_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_to(ctx, OTHER_ONLY_IP);
}

SETUP("tc", "02_cross_tenant_address_is_unroutable")
int cross_tenant_setup(struct __ctx_buff *ctx)
{
	populate_ipcache();
	endpoint_v4_add_entry_cluster(SENDER_IP, SENDER_TENANT, 0, 0, 0,
				      SENDER_IDENTITY, 0, NULL, NULL);

	/* Deliberately allow the identity the address has in the other tenant.
	 * The packet must still be dropped: isolation comes from the address
	 * being unresolvable in this tenant, not from a policy denial, so even an
	 * explicit allow cannot let it through.
	 */
	policy_add_egress_allow_l3_l4_entry(OTHER_ONLY_IDENTITY, IPPROTO_TCP,
					    DST_PORT, 0);

	return pod_send_packet(ctx);
}

CHECK("tc", "02_cross_tenant_address_is_unroutable")
int cross_tenant_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_DROP)
		test_fatal("cross-tenant packet was not dropped, status %d", *status_code);

	test_finish();
}
