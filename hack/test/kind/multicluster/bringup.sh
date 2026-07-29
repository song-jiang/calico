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

# bringup.sh - Phase 1 bring-up of the two-cluster / two-ToR BGP fabric.
#
# Steps:
#   1. Create 3 docker networks (rack-a, rack-b, fabric).
#   2. Start the shared kind-registry and connect it to both rack networks.
#   3. Create two KIND clusters, one per rack network (split pod/service CIDRs).
#   4. Build Calico dev images (once) and install Calico on each cluster.
#   5. Start two calico/bird ToRs; peer each to its cluster's nodes and to the
#      other ToR over the fabric.
#   6. Apply Calico BGPConfiguration/BGPPeer on each cluster.
#   7. (optional, DEPLOY_MOCKVIRT=true) Deploy MockVirt + exchange CAs.
#   8. Verify BGP sessions, cross-cluster routes, and pod reachability.
#
# Env overrides: see common.sh (BIRD_IMAGE, DEPLOY_MOCKVIRT, KUBEVIRT_REPO).
# SKIP_CALICO_BUILD=true skips `make kind-build-images` (use existing images).

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

KINDEST_NODE_VERSION="${KINDEST_NODE_VERSION:-v1.35.5}"
CALICO_API_GROUP="projectcalico.org/v3"

# ---------------------------------------------------------------------------
# 1. Docker networks
# ---------------------------------------------------------------------------
create_network() {
  local name="$1" subnet="$2" subnet6="$3"
  if docker network inspect "${name}" >/dev/null 2>&1; then
    log "docker network ${name} already exists"
  else
    log "creating docker network ${name} (${subnet}, ${subnet6})"
    docker network create --subnet "${subnet}" --ipv6 --subnet "${subnet6}" "${name}" >/dev/null
  fi
}

create_networks() {
  create_network "${RACK_A_NET}" "${RACK_A_SUBNET}" "${RACK_A_SUBNET6}"
  create_network "${RACK_B_NET}" "${RACK_B_SUBNET}" "${RACK_B_SUBNET6}"
  create_network "${FABRIC_NET}" "${FABRIC_SUBNET}" "${FABRIC_SUBNET6}"
}

# ---------------------------------------------------------------------------
# 2. Registry (reused across both clusters; must reach both rack networks)
# ---------------------------------------------------------------------------
ensure_registry() {
  "${KIND_DIR}/registry.sh" up
  for net in "${RACK_A_NET}" "${RACK_B_NET}"; do
    if ! docker network inspect "${net}" -f '{{range .Containers}}{{.Name}} {{end}}' | grep -qw kind-registry; then
      log "connecting kind-registry to ${net}"
      docker network connect "${net}" kind-registry
    fi
  done
}

# ---------------------------------------------------------------------------
# 3. Clusters (reuse the repo's kind-cluster-create: CRDs, registry config)
# ---------------------------------------------------------------------------
create_cluster() {
  local name="$1" config="$2" network="$3" kubeconfig="$4"
  if [ "${REUSE_CLUSTERS}" = "true" ] && "${KIND}" get clusters 2>/dev/null | grep -qx "${name}"; then
    log "reusing existing KIND cluster ${name} (REUSE_CLUSTERS=true)"
    "${KIND}" export kubeconfig --name "${name}" --kubeconfig "${kubeconfig}" >/dev/null 2>&1 || true
    return
  fi
  log "creating KIND cluster ${name} on docker network ${network}"
  KIND_EXPERIMENTAL_DOCKER_NETWORK="${network}" \
    make -C "${REPO_ROOT}" kind-cluster-create \
      KIND_CONFIG="${config}" \
      KIND_KUBECONFIG="${kubeconfig}" \
      CALICO_API_GROUP="${CALICO_API_GROUP}" \
      KINDEST_NODE_VERSION="${KINDEST_NODE_VERSION}"
}

# ---------------------------------------------------------------------------
# 4. Calico install (reuse kind-deploy; overlay per-cluster values)
# ---------------------------------------------------------------------------
install_calico() {
  local name="$1" config="$2" kubeconfig="$3" overlay="$4"
  if [ "${REUSE_CLUSTERS}" = "true" ] && \
     kctl "${kubeconfig}" wait --for=condition=Ready pod -l k8s-app=calico-node -n calico-system --timeout=5s >/dev/null 2>&1; then
    log "Calico already Ready on ${name}, skipping install (REUSE_CLUSTERS=true)"
    return
  fi
  log "installing Calico on ${name}"
  # KIND_SKIP_LB_POOLS: this harness is IPv4-only and needs no LoadBalancer
  # pools. Without it, deploy_resources.sh applies the fdff::/64 LB-only pool,
  # which flips the operator's CNI config to assign_ipv6=true (it enables v6
  # whenever ANY enabled v6 pool exists, ignoring allowedUses) and every
  # subsequent pod ADD fails with "no pools match the required use (Workload)".
  KIND_SKIP_LB_POOLS=true \
  EXTRA_VALUES_FILES="${overlay}" \
    make -C "${REPO_ROOT}" kind-deploy \
      KIND_CONFIG="${config}" \
      KIND_KUBECONFIG="${kubeconfig}" \
      KIND_CALICO_API_GROUP="${CALICO_API_GROUP}"
}

# ---------------------------------------------------------------------------
# 5. ToRs (calico/bird acting as a rack's top-of-rack router)
# ---------------------------------------------------------------------------
start_tor() {
  local tor="$1" rack_net="$2" rack_ip="$3" fabric_ip="$4"
  log "starting ToR ${tor} (rack ${rack_ip}, fabric ${fabric_ip})"
  docker rm -f "${tor}" >/dev/null 2>&1 || true
  docker run -d --privileged --name "${tor}" \
    --net "${rack_net}" --ip "${rack_ip}" "${BIRD_IMAGE}" >/dev/null
  docker network connect "${FABRIC_NET}" --ip "${fabric_ip}" "${tor}"
  # Wait for the container to be usable.
  for _ in $(seq 1 30); do docker exec "${tor}" true 2>/dev/null && break; sleep 1; done
  docker exec "${tor}" apk add --no-cache curl iproute2 >/dev/null
  # A ToR forwards between its rack and the fabric, so enable IP forwarding
  # (the k8st external-node pattern doesn't, since it's only a peer).
  docker exec "${tor}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  docker exec "${tor}" sysctl -w net.ipv4.fib_multipath_hash_policy=1 >/dev/null
  docker exec "${tor}" sed -i '/protocol kernel {/a merge paths on;' /etc/bird.conf
}

# configure_tor_bgp writes /etc/bird/peers.conf: one eBGP session per cluster
# node plus one to the peer ToR over the fabric. `next hop self` makes routes
# re-advertised across the fabric usable by each side (the peer ToR's fabric IP
# isn't reachable from the rack, and vice versa).
configure_tor_bgp() {
  local tor="$1" local_as="$2" cluster_as="$3" other_fabric_ip="$4" other_as="$5"; shift 5
  local node_ips=("$@")
  local tmp; tmp="$(mktemp)"
  {
    echo "# Generated by bringup.sh for ${tor}"
    echo "template bgp bgp_tpl {"
    echo "  debug { states };"
    echo "  local as ${local_as};"
    echo "  import all;"
    echo "  export all;"
    echo "  next hop self;"
    echo "  add paths on;"
    echo "  connect delay time 2;"
    echo "  connect retry time 5;"
    echo "  error wait time 5,30;"
    echo "}"
    local i=0
    for ip in "${node_ips[@]}"; do
      echo "protocol bgp node_${i} from bgp_tpl { neighbor ${ip} as ${cluster_as}; }"
      i=$((i + 1))
    done
    echo "protocol bgp fabric_peer from bgp_tpl { neighbor ${other_fabric_ip} as ${other_as}; }"
  } >"${tmp}"
  docker cp "${tmp}" "${tor}:/etc/bird/peers.conf"
  rm -f "${tmp}"
  docker exec "${tor}" birdcl configure
}

node_ips() {  # node_ips <kubeconfig> -> InternalIPs (one per line)
  kctl "$1" get nodes \
    -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}'
}

# ---------------------------------------------------------------------------
# 6. Calico BGP objects
# ---------------------------------------------------------------------------
apply_calico_bgp() {
  local kubeconfig="$1" manifest="$2"
  log "applying $(basename "${manifest}")"
  kctl "${kubeconfig}" apply -f "${manifest}"
}

# ---------------------------------------------------------------------------
# 7. MockVirt (BLOCKED on the GCR sync-controller image; gated off by default)
# ---------------------------------------------------------------------------
deploy_mockvirt() {
  [ -f "${MOCKVIRT_OPERATOR_MANIFEST}" ] || die "operator manifest not found at ${MOCKVIRT_OPERATOR_MANIFEST} — build MockVirt dev images first (see README: hack/ci-push-images.sh with DOCKER_PREFIX=docker.io/songtjiang)"
  [ -f "${MOCKVIRT_CR_MANIFEST}" ] || die "CR manifest not found at ${MOCKVIRT_CR_MANIFEST}"
  for kc in "${CLUSTER_A_KUBECONFIG}" "${CLUSTER_B_KUBECONFIG}"; do
    log "deploying MockVirt on $(basename "${kc}") using $(basename "${MOCKVIRT_OPERATOR_MANIFEST}")"
    kctl "${kc}" apply -f "${MOCKVIRT_OPERATOR_MANIFEST}"
    kctl "${kc}" apply -f "${MOCKVIRT_CR_MANIFEST}"
  done
  for kc in "${CLUSTER_A_KUBECONFIG}" "${CLUSTER_B_KUBECONFIG}"; do
    log "waiting for virt-synchronization-controller on $(basename "${kc}") (proves the gate took effect)"
    for _ in $(seq 1 60); do
      kctl "${kc}" -n kubevirt get deploy virt-synchronization-controller >/dev/null 2>&1 && break
      sleep 5
    done
  done
  exchange_ca
}

# exchange_ca copies each cluster's kubevirt-ca bundle into the other's
# kubevirt-external-ca ConfigMap so the sync-controllers trust each other.
exchange_ca() {
  log "exchanging kubevirt CA bundles between clusters"
  local ca_a ca_b
  ca_a="$(kctl "${CLUSTER_A_KUBECONFIG}" -n kubevirt get cm kubevirt-ca -o jsonpath='{.data.ca-bundle}')"
  ca_b="$(kctl "${CLUSTER_B_KUBECONFIG}" -n kubevirt get cm kubevirt-ca -o jsonpath='{.data.ca-bundle}')"
  kctl "${CLUSTER_A_KUBECONFIG}" -n kubevirt create cm kubevirt-external-ca \
    --from-literal=ca-bundle="${ca_b}" --dry-run=client -o yaml | kctl "${CLUSTER_A_KUBECONFIG}" apply -f -
  kctl "${CLUSTER_B_KUBECONFIG}" -n kubevirt create cm kubevirt-external-ca \
    --from-literal=ca-bundle="${ca_a}" --dry-run=client -o yaml | kctl "${CLUSTER_B_KUBECONFIG}" apply -f -
}

# ---------------------------------------------------------------------------
# 8. Verification (Phase 1 success criteria 1-4)
# ---------------------------------------------------------------------------
verify() {
  log "===== verification ====="
  local ok=0

  log "BGP protocols on ${TOR_A}:"; docker exec "${TOR_A}" birdcl show protocols || true
  log "BGP protocols on ${TOR_B}:"; docker exec "${TOR_B}" birdcl show protocols || true

  log "routes on ${TOR_A} (expect cluster-b 10.245.x):"
  docker exec "${TOR_A}" birdcl show route | grep -E "10.245\." && log "  tor-a sees cluster-b pods" || { warn "  tor-a missing cluster-b routes"; ok=1; }
  log "routes on ${TOR_B} (expect cluster-a 10.244.x):"
  docker exec "${TOR_B}" birdcl show route | grep -E "10.244\." && log "  tor-b sees cluster-a pods" || { warn "  tor-b missing cluster-a routes"; ok=1; }

  log "cross-cluster pod reachability test"
  kctl "${CLUSTER_A_KUBECONFIG}" run mc-pinger --image busybox --restart=Never --command -- sleep 3600 >/dev/null 2>&1 || true
  kctl "${CLUSTER_B_KUBECONFIG}" run mc-target --image busybox --restart=Never --command -- sleep 3600 >/dev/null 2>&1 || true
  kctl "${CLUSTER_A_KUBECONFIG}" wait --for=condition=Ready pod/mc-pinger --timeout=120s || true
  kctl "${CLUSTER_B_KUBECONFIG}" wait --for=condition=Ready pod/mc-target --timeout=120s || true
  local target_ip
  target_ip="$(kctl "${CLUSTER_B_KUBECONFIG}" get pod mc-target -o jsonpath='{.status.podIP}')"
  log "cluster-b target pod IP: ${target_ip}"
  if kctl "${CLUSTER_A_KUBECONFIG}" exec mc-pinger -- ping -c3 -W2 "${target_ip}"; then
    log "  PASS: cluster-a pod reached cluster-b pod ${target_ip}"
  else
    warn "  FAIL: cluster-a pod could not reach cluster-b pod ${target_ip}"; ok=1
  fi
  kctl "${CLUSTER_A_KUBECONFIG}" delete pod mc-pinger --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kctl "${CLUSTER_B_KUBECONFIG}" delete pod mc-target --ignore-not-found --wait=false >/dev/null 2>&1 || true

  if [ "${ok}" -eq 0 ]; then
    log "===== Phase 1 fabric is UP ====="
  else
    warn "===== verification had failures (see above) ====="
  fi
  return "${ok}"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  # Two KIND clusters' pods share the host's per-user inotify budget; at the
  # default max_user_instances=128, virt-handler CrashLoops with "Failed to
  # create an inotify watcher: too many open files".
  local inotify_max
  inotify_max="$(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo 0)"
  if [ "${inotify_max}" -lt 512 ]; then
    warn "fs.inotify.max_user_instances=${inotify_max} is too low for two KIND clusters + MockVirt."
    warn "Run: sudo sysctl -w fs.inotify.max_user_instances=1024 fs.inotify.max_user_watches=1048576"
  fi

  create_networks
  ensure_registry

  create_cluster "${CLUSTER_A}" "${MC_DIR}/cluster-a.config" "${RACK_A_NET}" "${CLUSTER_A_KUBECONFIG}"
  create_cluster "${CLUSTER_B}" "${MC_DIR}/cluster-b.config" "${RACK_B_NET}" "${CLUSTER_B_KUBECONFIG}"

  if [ "${SKIP_CALICO_BUILD:-false}" != "true" ]; then
    log "building Calico dev images into the local registry (SKIP_CALICO_BUILD=true to skip)"
    make -C "${REPO_ROOT}" kind-build-images
  fi
  install_calico "${CLUSTER_A}" "${MC_DIR}/cluster-a.config" "${CLUSTER_A_KUBECONFIG}" "${MC_DIR}/values-cluster-a.yaml"
  install_calico "${CLUSTER_B}" "${MC_DIR}/cluster-b.config" "${CLUSTER_B_KUBECONFIG}" "${MC_DIR}/values-cluster-b.yaml"

  start_tor "${TOR_A}" "${RACK_A_NET}" "${TOR_A_RACK_IP}" "${TOR_A_FABRIC_IP}"
  start_tor "${TOR_B}" "${RACK_B_NET}" "${TOR_B_RACK_IP}" "${TOR_B_FABRIC_IP}"

  mapfile -t a_nodes < <(node_ips "${CLUSTER_A_KUBECONFIG}")
  mapfile -t b_nodes < <(node_ips "${CLUSTER_B_KUBECONFIG}")
  log "cluster-a node IPs: ${a_nodes[*]}"
  log "cluster-b node IPs: ${b_nodes[*]}"
  configure_tor_bgp "${TOR_A}" "${TOR_A_AS}" "${CLUSTER_A_AS}" "${TOR_B_FABRIC_IP}" "${TOR_B_AS}" "${a_nodes[@]}"
  configure_tor_bgp "${TOR_B}" "${TOR_B_AS}" "${CLUSTER_B_AS}" "${TOR_A_FABRIC_IP}" "${TOR_A_AS}" "${b_nodes[@]}"

  apply_calico_bgp "${CLUSTER_A_KUBECONFIG}" "${MC_DIR}/bgp-cluster-a.yaml"
  apply_calico_bgp "${CLUSTER_B_KUBECONFIG}" "${MC_DIR}/bgp-cluster-b.yaml"

  if [ "${DEPLOY_MOCKVIRT}" = "true" ]; then
    deploy_mockvirt
  else
    log "DEPLOY_MOCKVIRT != true - skipping MockVirt deploy (set DEPLOY_MOCKVIRT=true to deploy from the docker.io/songtjiang images)"
  fi

  log "waiting 20s for BGP sessions to establish..."
  sleep 20
  verify || warn "verification reported issues"

  log "done. kubeconfigs:"
  log "  cluster-a: ${CLUSTER_A_KUBECONFIG}"
  log "  cluster-b: ${CLUSTER_B_KUBECONFIG}"
}

main "$@"
