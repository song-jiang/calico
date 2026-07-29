#!/usr/bin/env bash

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# common.sh - shared configuration for the two-cluster / two-ToR BGP harness
# (Phase 1). Sourced by bringup.sh, teardown.sh, and verify.sh.
#
# Topology (simulates two on-prem racks joined by a BGP fabric):
#
#   rack-a 172.31.0.0/24        fabric 172.30.0.0/29        rack-b 172.32.0.0/24
#    cluster-a AS65101           tor-a.2 <-eBGP-> .3 tor-b   cluster-b AS65102
#    pods 10.244.0.0/16           (AS65001)   (AS65002)      pods 10.245.0.0/16
#      nodes -eBGP-> tor-a                        tor-b <-eBGP- nodes
#
# Because MockVirt's FakeDomainManager never opens a real QEMU migration
# stream, the only cross-cluster traffic that matters for decentralized live
# migration is the sync-controller gRPC (pod IP : 9185). Phase 1 proves that
# pod IPs are routable between the two clusters over plain BGP. Phase 2 will
# swap the bird ToRs for FRR and add EVPN-VXLAN on the tor-a <-> tor-b link.

set -euo pipefail

# --- Paths -------------------------------------------------------------------
MC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${MC_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${KIND_DIR}/../../.." && pwd)"
KIND="${KIND:-${KIND_DIR}/kind}"
KUBECTL="${KUBECTL:-${KIND_DIR}/kubectl}"

# --- Docker networks (the "racks" + the inter-ToR "fabric") ------------------
RACK_A_NET="rack-a"
RACK_B_NET="rack-b"
FABRIC_NET="fabric"
RACK_A_SUBNET="172.31.0.0/24"
RACK_B_SUBNET="172.32.0.0/24"
# /29 gives usable hosts .2...6 after Docker reserves .1 as the gateway; we need
# two (one per ToR). A /30 would leave only one usable host.
FABRIC_SUBNET="172.30.0.0/29"
# The networks are dual-stack: the clusters/BGP are IPv4-only, but the repo's
# deploy_resources.sh unconditionally runs `ip -6 addr replace 2001:20::.../64`
# on each node, which errors ("IPv6 is disabled on this device") on an
# IPv4-only docker network. Enabling IPv6 on the networks satisfies that step;
# Calico still runs v4-only (values overlay sets nodeAddressAutodetectionV6=null).
RACK_A_SUBNET6="fd00:31::/64"
RACK_B_SUBNET6="fd00:32::/64"
FABRIC_SUBNET6="fd00:30::/64"

# --- ToR routers (calico/bird; swap to FRR in Phase 2 for EVPN-VXLAN) --------
# calico/bird tag mirrors node/Makefile BIRD_IMAGE (BIRD_VERSION-ARCH).
BIRD_IMAGE="${BIRD_IMAGE:-calico/bird:v0.3.3-211-g9111ec3c-amd64}"

# ToR rack IPs use a HIGH host number (.253): Docker auto-assigns node/registry
# container IPs from the low end of the subnet (.2, .3, ...), so a low static IP
# collides ("Address already in use"). Keep these in sync with peerIP in
# bgp-cluster-{a,b}.yaml. Fabric IPs are safe at .2/.3 (only the two ToRs attach
# to the fabric network).
TOR_A="tor-a"
TOR_A_RACK_IP="172.31.0.253"
TOR_A_FABRIC_IP="172.30.0.2"
TOR_A_AS="65001"

TOR_B="tor-b"
TOR_B_RACK_IP="172.32.0.253"
TOR_B_FABRIC_IP="172.30.0.3"
TOR_B_AS="65002"

# --- Clusters ----------------------------------------------------------------
CLUSTER_A="cluster-a"
CLUSTER_A_AS="65101"
CLUSTER_A_KUBECONFIG="${MC_DIR}/${CLUSTER_A}-kubeconfig.yaml"

CLUSTER_B="cluster-b"
CLUSTER_B_AS="65102"
CLUSTER_B_KUBECONFIG="${MC_DIR}/${CLUSTER_B}-kubeconfig.yaml"

# --- Optional MockVirt stage -------------------------------------------------
# Set DEPLOY_MOCKVIRT=true after building the MockVirt dev images from the
# current branch and pushing them to your Docker Hub (see README). During dev we
# use personal images (e.g. docker.io/songtjiang/virt-*:mc-dev), NOT the stable
# quay.io/tigeradev images; the CI push to tigeradev happens only once the code
# is proven.
#
# hack/ci-push-images.sh regenerates the operator manifest under
# _out/manifests/release/ pointing at whatever DOCKER_PREFIX/DOCKER_TAG you
# built, so the harness is manifest-driven (no registry hardcoded here). The CR
# is registry-agnostic (config only), so it comes straight from the source tree.
# REUSE_CLUSTERS=true skips cluster creation + Calico install when a cluster
# already exists and calico-node is Ready — for fast iteration on the ToR/BGP
# steps without recreating healthy clusters.
REUSE_CLUSTERS="${REUSE_CLUSTERS:-false}"
DEPLOY_MOCKVIRT="${DEPLOY_MOCKVIRT:-false}"
KUBEVIRT_REPO="${KUBEVIRT_REPO:-${HOME}/go/src/github.com/kubevirt/kubevirt}"
MOCKVIRT_OPERATOR_MANIFEST="${MOCKVIRT_OPERATOR_MANIFEST:-${KUBEVIRT_REPO}/_out/manifests/release/kubevirt-operator.yaml}"
MOCKVIRT_CR_MANIFEST="${MOCKVIRT_CR_MANIFEST:-${KUBEVIRT_REPO}/manifests/release/kubevirt-cr-multicluster.yaml}"

log()  { echo -e "\033[1;34m[mc]\033[0m $*"; }
warn() { echo -e "\033[1;33m[mc]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[mc]\033[0m $*" >&2; exit 1; }

# kctl <kubeconfig> <args...> - run kubectl against a specific cluster.
kctl() {
  local kubeconfig="$1"; shift
  KUBECONFIG="${kubeconfig}" "${KUBECTL}" "$@"
}
