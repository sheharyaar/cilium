#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
#
# End-to-end check for overlapping-CIDR multi-tenancy on kind.
#
# Two tenants are given the same pod CIDR and the connectivity matrix between
# them is asserted. Every assertion prints PASS or FAIL and the script exits
# non-zero if any of them failed, so it is usable as a gate.
#
# Prerequisites (not installed by this script):
#   kind, kubectl, docker, and the cilium CLI
#
# Usage:
#   make kind WORKERS=2
#   make kind-image
#   test/tenancy/run.sh install     # install Cilium with tenancy enabled
#   test/tenancy/run.sh             # apply manifests and run the assertions

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="${SCRIPT_DIR}/manifests"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CILIUM_CLI="${CILIUM_CLI:-cilium}"
TIMEOUT="${TIMEOUT:-180s}"

failures=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }
info() { printf '\n==> %s\n' "$1"; }

# assert <description> <expected-exit> <command...>
assert() {
	local desc="$1" want="$2"
	shift 2
	local out
	out="$("$@" 2>&1)"
	local got=$?
	if [ "$got" -eq "$want" ]; then
		pass "$desc"
	else
		fail "$desc (exit ${got}, want ${want})"
		printf '      %s\n' "${out}" | head -5
	fi
}

pod_in() { # <namespace> <app>
	kubectl -n "$1" get pod -l "app=$2" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

pod_ip() { # <namespace> <app>
	kubectl -n "$1" get pod -l "app=$2" -o jsonpath='{.items[0].status.podIP}' 2>/dev/null
}

curl_from() { # <namespace> <app> <url>
	kubectl -n "$1" exec "$(pod_in "$1" "$2")" -- \
		curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$3"
}

install_cilium() {
	info "Installing Cilium with tenancy enabled"
	"${CILIUM_CLI}" uninstall >/dev/null 2>&1 || true
	"${CILIUM_CLI}" install \
		--chart-directory="${ROOT_DIR}/install/kubernetes/cilium" \
		--version= \
		--wait \
		--set=ipam.mode=multi-pool \
		--set=routingMode=tunnel \
		--set=tunnelProtocol=geneve \
		--set=kubeProxyReplacement=true \
		--set=enableIPv6=false \
		--set=extraArgs='{--enable-tenancy}'
}

if [ "${1:-}" = "install" ]; then
	install_cilium
	exit $?
fi

info "Applying tenancy manifests"
kubectl apply -f "${MANIFESTS}/" >/dev/null

info "Waiting for tenant IDs to be allocated"
for tenant in acme globex; do
	for _ in $(seq 1 60); do
		id="$(kubectl get ciliumtenant "${tenant}" -o jsonpath='{.status.tenantID}' 2>/dev/null)"
		[ -n "${id}" ] && [ "${id}" != "0" ] && break
		sleep 2
	done
done

ACME_ID="$(kubectl get ciliumtenant acme -o jsonpath='{.status.tenantID}')"
GLOBEX_ID="$(kubectl get ciliumtenant globex -o jsonpath='{.status.tenantID}')"

if [ -n "${ACME_ID}" ] && [ "${ACME_ID}" != "0" ] &&
	[ -n "${GLOBEX_ID}" ] && [ "${GLOBEX_ID}" != "0" ] &&
	[ "${ACME_ID}" != "${GLOBEX_ID}" ]; then
	pass "0. operator allocated distinct tenant IDs (acme=${ACME_ID} globex=${GLOBEX_ID})"
else
	fail "0. operator allocated distinct tenant IDs (acme=${ACME_ID:-none} globex=${GLOBEX_ID:-none})"
	echo "Cannot continue without tenant IDs."
	exit 1
fi

info "Waiting for workloads"
# Wait for an IP rather than for Ready. These workloads define no probes so they
# do become Ready, but an IP is what the assertions need and it appears first.
# A tenant pod WITH a readinessProbe would never become ready: kubelet has no
# route to a tenant pod. See TESTING.md.
for ns in acme globex; do
	for app in server client; do
		for _ in $(seq 1 90); do
			[ -n "$(pod_ip "${ns}" "${app}")" ] && break
			sleep 2
		done
	done
done
kubectl -n acme wait --for=jsonpath='{.status.podIP}' --timeout="${TIMEOUT}" \
	pod -l app=egress-gateway >/dev/null 2>&1 || true

ACME_SERVER_IP="$(pod_ip acme server)"
GLOBEX_SERVER_IP="$(pod_ip globex server)"

info "Assertions"

# 1. Both tenants allocated out of the same CIDR. Identical addresses are the
#    strongest form of the result but not guaranteed, so the assertion is that
#    both came from the shared pool.
if [[ "${ACME_SERVER_IP}" == 10.64.* && "${GLOBEX_SERVER_IP}" == 10.64.* ]]; then
	if [ "${ACME_SERVER_IP}" = "${GLOBEX_SERVER_IP}" ]; then
		pass "1. overlapping CIDRs: both tenants got the SAME address ${ACME_SERVER_IP}"
	else
		pass "1. overlapping CIDRs: both tenants allocated from 10.64.0.0/16 (${ACME_SERVER_IP}, ${GLOBEX_SERVER_IP})"
	fi
else
	fail "1. overlapping CIDRs (acme=${ACME_SERVER_IP:-none} globex=${GLOBEX_SERVER_IP:-none})"
fi

# 2. In-tenant pod to pod, across nodes.
assert "2. in-tenant cross-node pod to pod (acme)" 0 \
	curl_from acme client "http://${ACME_SERVER_IP}/"
assert "2. in-tenant cross-node pod to pod (globex)" 0 \
	curl_from globex client "http://${GLOBEX_SERVER_IP}/"

# 3. Cross-tenant must fail. With identical addresses this is the decisive test:
#    the same packet that works inside a tenant must not work across one.
assert "3. cross-tenant pod to pod is blocked" 28 \
	curl_from acme client "http://${GLOBEX_SERVER_IP}/"

# 4. In-tenant ClusterIP.
#
# By VIP, not by name. Resolving a name needs kube-dns, which lives in the
# default VPC and is therefore unreachable from inside a tenant; per-tenant DNS
# is a documented deployment requirement, not something under test here.
ACME_SVC_IP="$(kubectl -n acme get svc server -o jsonpath='{.spec.clusterIP}')"
GLOBEX_SVC_IP="$(kubectl -n globex get svc server -o jsonpath='{.spec.clusterIP}')"
assert "4. in-tenant ClusterIP (acme ${ACME_SVC_IP})" 0 \
	curl_from acme client "http://${ACME_SVC_IP}/"
assert "4. in-tenant ClusterIP (globex ${GLOBEX_SVC_IP})" 0 \
	curl_from globex client "http://${GLOBEX_SVC_IP}/"

# 5. NodePort from outside the cluster, into a tenant backend, for both tenants
#    whose backends may share an address.
NODE_IP="$(kubectl get node kind-worker -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1)"
for pair in "acme:31080" "globex:31081"; do
	tenant="${pair%%:*}"
	port="${pair##*:}"
	code="$(docker run --rm --network kind-cilium curlimages/curl:8.10.1 \
		-sS --max-time 5 -o /dev/null -w '%{http_code}' \
		"http://${NODE_IP}:${port}/" 2>/dev/null)"
	if [ "${code}" = "200" ]; then
		pass "5. NodePort into ${tenant} backend (${NODE_IP}:${port})"
	else
		fail "5. NodePort into ${tenant} backend (${NODE_IP}:${port}, got '${code:-no response}')"
	fi
done

# 6. Egress through the tenant's gateway. acme has one, globex does not, so the
#    same request must succeed for acme and fail for globex.
EXTERNAL="${EXTERNAL:-1.1.1.1}"
assert "6. egress via tenant gateway (acme)" 0 \
	curl_from acme client "http://${EXTERNAL}/"
assert "6. egress blocked without a gateway (globex)" 28 \
	curl_from globex client "http://${EXTERNAL}/"

info "Summary"
if [ "${failures}" -eq 0 ]; then
	echo "All assertions passed."
	exit 0
fi
echo "${failures} assertion(s) failed."
exit 1
