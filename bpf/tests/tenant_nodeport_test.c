// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* NodePort into a tenant backend.
 *
 * An external client hits a NodePort on this node and the service selects a
 * backend that lives in a tenant. Another tenant holds an endpoint at the very
 * same address, which is legal under overlapping-CIDR multi-tenancy, so the
 * backend address alone no longer identifies an endpoint.
 *
 * Two things therefore have to carry the tenant: the endpoint lookup that
 * decides whether the backend is local, and the metadata handed to the delivery
 * path afterwards. If either is tenant-blind the packet is delivered to the
 * wrong pod, or to no pod at all.
 *
 * Frontends stay in the default VPC: node IPs and service VIPs are unique
 * cluster-wide, so nothing about the service key changes.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define TUNNEL_MODE
#define ENCAP_IFINDEX 1

#define ENABLE_NODEPORT
/* Without host routing the from-netdev path returns before the local delivery
 * leg, so the tenant-scoped lookup under test would never run.
 */
#define ENABLE_HOST_ROUTING
#define ENABLE_CLUSTER_AWARE_ADDRESSING
/* Tells the NodePort path that the ID on a backend is a tenant, not a remote
 * ClusterMesh cluster.
 */
#define ENABLE_TENANCY

#include <bpf/config/node.h>

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		tcp_src_one

#define FRONTEND_IP		v4_node_one
#define FRONTEND_PORT		tcp_svc_one

/* One backend address, two tenants. */
#define BACKEND_IP		v4_pod_one
#define BACKEND_PORT		tcp_dst_one

#define TENANT_ONE		1
#define TENANT_TWO		2
#define TENANT_ONE_IFINDEX	111
#define TENANT_TWO_IFINDEX	222

#define TENANT_ONE_MAC		mac_one
#define TENANT_TWO_MAC		mac_three
#define NODE_MAC		mac_two
#define CLIENT_MAC		mac_four

#define TENANT_ONE_IDENTITY	((TENANT_ONE << 16) | 0xff01)
#define TENANT_TWO_IDENTITY	((TENANT_TWO << 16) | 0xff02)

#define REV_NAT_INDEX		1

/* The interface the reply leaves on. Kept equal to what the mocked FIB lookup
 * reports so nodeport_fib_lookup_and_redirect() returns CTX_ACT_OK instead of
 * redirecting, and the reverse-NAT that follows it actually runs.
 */
#define HOST_IFINDEX		1

#undef EVENT_SOURCE

/* The test namespace has no routes, so the real FIB lookup fails with
 * BPF_FIB_LKUP_RET_NOT_FWDED and the reply is dropped before it reaches the
 * reverse-NAT. Mock it out; routing is not what is under test here.
 */
#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused struct __ctx_buff * volatile ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	/* The verifier checks this function in isolation and cannot see that
	 * params is non-NULL at every call site.
	 */
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;

	params->ifindex = HOST_IFINDEX;
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include "lib/bpf_host.h"

ASSIGN_CONFIG(__u32, cluster_id, 0)
ASSIGN_CONFIG(__u32, interface_ifindex, HOST_IFINDEX)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

static __always_inline int
pktgen_from_client(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)CLIENT_MAC,
					  (__u8 *)NODE_MAC,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
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

/* Both tenants hold the backend address. Tenant two is added last so that a
 * lookup keyed on address alone would tend to find it.
 */
static __always_inline void add_both_tenant_endpoints(void)
{
	endpoint_v4_add_entry_cluster(BACKEND_IP, TENANT_ONE, TENANT_ONE_IFINDEX, 0, 0,
				      TENANT_ONE_IDENTITY, 0,
				      (__u8 *)TENANT_ONE_MAC, (__u8 *)NODE_MAC);
	endpoint_v4_add_entry_cluster(BACKEND_IP, TENANT_TWO, TENANT_TWO_IFINDEX, 0, 0,
				      TENANT_TWO_IDENTITY, 0,
				      (__u8 *)TENANT_TWO_MAC, (__u8 *)NODE_MAC);
}

/* Flagged as a NodePort rather than a plain service. That is what makes
 * nodeport_svc_lb4() stamp node_port on the conntrack entry it creates, which
 * in turn is what the reply direction reads to decide there is a reverse-NAT to
 * undo. Without the flag the forward cases below still pass and the reply case
 * has nothing to find.
 */
static __always_inline void add_service_for_tenant(__u8 tenant)
{
	lb_v4_add_nodeport_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1,
				   REV_NAT_INDEX, 0);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 1,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_TCP, tenant);
}

/* 01: the service selects a backend in tenant one, so the packet must be
 * delivered to tenant one's endpoint even though tenant two holds the same
 * address.
 */
PKTGEN("tc", "01_nodeport_to_tenant_one")
int nodeport_tenant_one_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_client(ctx);
}

SETUP("tc", "01_nodeport_to_tenant_one")
int nodeport_tenant_one_setup(struct __ctx_buff *ctx)
{
	add_both_tenant_endpoints();
	add_service_for_tenant(TENANT_ONE);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "01_nodeport_to_tenant_one")
int nodeport_tenant_one_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct tcphdr *l4;
	struct iphdr *l3;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* The service was translated: proof the NodePort path ran at all. */
	if (l3->daddr != BACKEND_IP)
		test_fatal("packet was not DNATed to the backend");

	if (l4->dest != BACKEND_PORT)
		test_fatal("destination port was not translated");

	/* The rewritten destination MAC is what says which of the two same-address
	 * endpoints the packet went to. Asserted positively: a tenant-blind
	 * lookup finds neither endpoint and leaves the MAC alone, which a
	 * "not the other tenant" check would accept.
	 */
	if (memcmp(l2->h_dest, (__u8 *)TENANT_ONE_MAC, ETH_ALEN) != 0)
		test_fatal("not delivered to tenant one's endpoint");

	test_finish();
}

/* 02: the mirror image. Same service, same backend address, but the backend is
 * in tenant two. A tenant-blind implementation cannot get both this and the
 * previous case right.
 */
PKTGEN("tc", "02_nodeport_to_tenant_two")
int nodeport_tenant_two_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_client(ctx);
}

SETUP("tc", "02_nodeport_to_tenant_two")
int nodeport_tenant_two_setup(struct __ctx_buff *ctx)
{
	add_both_tenant_endpoints();
	add_service_for_tenant(TENANT_TWO);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "02_nodeport_to_tenant_two")
int nodeport_tenant_two_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *l3;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->daddr != BACKEND_IP)
		test_fatal("packet was not DNATed to the backend");

	if (memcmp(l2->h_dest, (__u8 *)TENANT_TWO_MAC, ETH_ALEN) != 0)
		test_fatal("not delivered to tenant two's endpoint");

	test_finish();
}

/* 03 and 04 are one flow in two halves: the request that creates the conntrack
 * entry, then the backend's reply that has to find it again.
 *
 * This pair exists because its absence let a real bug ship. The forward cases
 * above passed the whole time the reply was leaving un-reverse-NATed, because
 * nothing ever exercised the return direction. The two halves must stay
 * adjacent and in order; the reply half depends on the state the request half
 * leaves in the maps.
 *
 * What is actually under test is that the forward and reply directions agree on
 * *which conntrack map* holds the entry. They run in different programs --
 * nodeport_svc_lb4() in from-netdev writes it, nodeport_rev_dnat_fwd_ipv4() in
 * to-netdev reads it -- and only the first of those knows the backend's tenant.
 * Scope the write to the tenant and the read finds nothing.
 */
PKTGEN("tc", "03_nodeport_request_to_tenant_one")
int nodeport_request_pktgen(struct __ctx_buff *ctx)
{
	return pktgen_from_client(ctx);
}

SETUP("tc", "03_nodeport_request_to_tenant_one")
int nodeport_request_setup(struct __ctx_buff *ctx)
{
	add_both_tenant_endpoints();
	add_service_for_tenant(TENANT_ONE);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "03_nodeport_request_to_tenant_one")
int nodeport_request_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *l3;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	/* Only a precondition for 04: the request has to have reached the
	 * backend for there to be a conntrack entry at all.
	 */
	if (l3->daddr != BACKEND_IP)
		test_fatal("request was not DNATed to the backend");

	if (memcmp(l2->h_dest, (__u8 *)TENANT_ONE_MAC, ETH_ALEN) != 0)
		test_fatal("request was not delivered to tenant one's endpoint");

	test_finish();
}

/* The backend answers. Source and destination are the reverse of the request
 * as it looked after DNAT.
 */
PKTGEN("tc", "04_nodeport_reply_is_reverse_natted")
int nodeport_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)TENANT_ONE_MAC,
					  (__u8 *)NODE_MAC,
					  BACKEND_IP, CLIENT_IP,
					  BACKEND_PORT, CLIENT_PORT);
	if (!l4)
		return TEST_ERROR;

	l4->syn = 1;
	l4->ack = 1;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "04_nodeport_reply_is_reverse_natted")
int nodeport_reply_setup(struct __ctx_buff *ctx)
{
	/* Deliberately no map setup. Everything this needs was left behind by
	 * 03, which is the point: the reply has to find the forward entry.
	 */
	return netdev_send_packet(ctx);
}

CHECK("tc", "04_nodeport_reply_is_reverse_natted")
int nodeport_reply_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct tcphdr *l4;
	struct iphdr *l3;
	struct ethhdr *l2;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* The whole point. The client contacted the frontend and must get an
	 * answer from the frontend; a reply still sourced from the backend
	 * address is one the client has no socket for and will discard.
	 *
	 * Asserted on the address and the port separately, because reverse-NAT
	 * rewrites both and getting only one right is a plausible half-failure.
	 */
	if (l3->saddr != FRONTEND_IP)
		test_fatal("reply was not reverse-NATed: source is still the backend address");

	if (l4->source != FRONTEND_PORT)
		test_fatal("reply source port was not translated back to the frontend");

	/* Untouched, so a wholesale rewrite would not pass by accident. */
	if (l3->daddr != CLIENT_IP)
		test_fatal("reply destination was rewritten");

	if (l4->dest != CLIENT_PORT)
		test_fatal("reply destination port was rewritten");

	test_finish();
}
