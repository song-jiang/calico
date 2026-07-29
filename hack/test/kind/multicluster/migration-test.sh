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

# migration-test.sh - drive one MockVirt DECENTRALIZED live migration from
# cluster-a to cluster-b over the BGP fabric and report Calico's behavior.
#
# Prereqs: bringup.sh has run with DEPLOY_MOCKVIRT=true (KubeVirt Available on
# both clusters, CAs exchanged). See README.md.
#
# Flow (mirrors the upstream decentralized-live-migration user guide):
#   1. cluster-a: VirtualMachine (runStrategy Always) -> VMI Running.
#   2. cluster-b: same VM with runStrategy WaitAsReceiver + VMIM spec.receive
#      -> receiver VMI in WaitingForSync, target virt-launcher pod up.
#   3. cluster-a: VMIM spec.sendTo with connectURL = cluster-b's
#      KubeVirt.status.synchronizationAddresses[0] (sync-controller POD IP:9185
#      -- the cross-cluster hop this whole harness exists to route).
#   4. Poll both sides until the source VMIM Succeeds and the target VMI runs.
#   5. Ping the migrated VM's (new) pod IP from cluster-a to prove the VM is
#      reachable across the fabric at its post-migration address.
#
# Env:
#   MIGRATION_ID        - override the generated migration ID
#   SKIP_TYPHA_RESTART  - "true" to skip the Typha restart (only needed once
#                         after MockVirt is first deployed; see below)
#   CLEANUP             - "true" to delete the VM/VMIMs from both clusters at
#                         the end (default: leave everything for inspection)
#   TIMEOUT_SECS        - migration wait budget (default 300)

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

VM_NAME="mc-vm"
VM_NS="default"
STAMP="$(date +%s)"
MIGRATION_ID="${MIGRATION_ID:-mc-mig-${STAMP}}"
VMIM_SEND="mc-vm-send-${STAMP}"
VMIM_RECV="mc-vm-recv-${STAMP}"
TIMEOUT_SECS="${TIMEOUT_SECS:-300}"

# The guestless VM spec: no disks/volumes so nothing needs pulling or booting;
# the FakeDomainManager fakes the domain either way. Both clusters must define
# the SAME VM (name + namespace); only runStrategy differs.
vm_manifest() { # vm_manifest <runStrategy>
  cat <<EOF
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: ${VM_NAME}
  namespace: ${VM_NS}
spec:
  runStrategy: $1
  template:
    metadata:
      labels:
        kubevirt.io/vm: ${VM_NAME}
      annotations:
        # Bridge binding is what Calico's live-migration support operates on:
        # the VM's IP IS the Calico-assigned pod IP (masquerade would NAT the
        # VM behind a private in-pod address, hiding it from Calico IPAM/routes).
        # This annotation is REQUIRED for a bridge-bound pod-network interface to
        # pass KubeVirt's live-migration webhook (otherwise rejected as
        # InterfaceNotLiveMigratable). Matches the Calico KubeVirt e2e suite
        # (e2e/pkg/tests/kubevirt/utils.go).
        kubevirt.io/allow-pod-bridge-network-live-migration: "true"
    spec:
      terminationGracePeriodSeconds: 0
      domain:
        memory:
          guest: 128Mi
        devices:
          interfaces:
          - name: default
            bridge: {}
      networks:
      - name: default
        pod: {}
EOF
}

vmi_phase()  { kctl "$1" get vmi  -n "${VM_NS}" "${VM_NAME}" -o jsonpath='{.status.phase}' 2>/dev/null || true; }
vmim_phase() { kctl "$1" get vmim -n "${VM_NS}" "$2" -o jsonpath='{.status.phase}' 2>/dev/null || true; }
vmi_ip()     { kctl "$1" get vmi  -n "${VM_NS}" "${VM_NAME}" -o jsonpath='{.status.interfaces[0].ipAddress}' 2>/dev/null || true; }
vmi_node()   { kctl "$1" get vmi  -n "${VM_NS}" "${VM_NAME}" -o jsonpath='{.status.nodeName}' 2>/dev/null || true; }

# --- 0. Clean slate for re-runs + one-time Typha kick ------------------------
log "cleaning any previous test VM/VMIMs (idempotent re-run)"
for kc in "${CLUSTER_A_KUBECONFIG}" "${CLUSTER_B_KUBECONFIG}"; do
  kctl "${kc}" delete vmim -n "${VM_NS}" --all --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kctl "${kc}" delete vm "${VM_NAME}" -n "${VM_NS}" --ignore-not-found >/dev/null 2>&1 || true
done
sleep 3

if [ "${SKIP_TYPHA_RESTART:-false}" != "true" ]; then
  # Typha watches VMIM resources for Felix's LiveMigration calculator. If
  # Calico came up before MockVirt (it did - bringup order), Typha's CRD
  # discovery missed the VMIM API and only retries every 30 minutes.
  # (Same workaround as kubevirt hack/ci-deploy-kind.sh.)
  for kc in "${CLUSTER_A_KUBECONFIG}" "${CLUSTER_B_KUBECONFIG}"; do
    log "restarting calico-typha on $(basename "${kc}") so Felix sees VMIMs"
    kctl "${kc}" -n calico-system rollout restart deployment calico-typha
  done
  for kc in "${CLUSTER_A_KUBECONFIG}" "${CLUSTER_B_KUBECONFIG}"; do
    kctl "${kc}" -n calico-system rollout status deployment calico-typha --timeout=2m
  done
fi

# --- 1. Source VM on cluster-a ------------------------------------------------
log "creating VM ${VM_NAME} on cluster-a (runStrategy Always)"
vm_manifest Always | kctl "${CLUSTER_A_KUBECONFIG}" apply -f -
log "waiting for source VMI to be Running"
for _ in $(seq 1 60); do
  [ "$(vmi_phase "${CLUSTER_A_KUBECONFIG}")" = "Running" ] && break
  sleep 5
done
[ "$(vmi_phase "${CLUSTER_A_KUBECONFIG}")" = "Running" ] || die "source VMI never reached Running: $(vmi_phase "${CLUSTER_A_KUBECONFIG}")"
SRC_IP="$(vmi_ip "${CLUSTER_A_KUBECONFIG}")"
SRC_NODE="$(vmi_node "${CLUSTER_A_KUBECONFIG}")"
log "source VMI Running on ${SRC_NODE}, IP ${SRC_IP}"

# --- 2. Receiver on cluster-b --------------------------------------------------
log "creating receiver VM (WaitAsReceiver) + VMIM receive on cluster-b (migrationID ${MIGRATION_ID})"
vm_manifest WaitAsReceiver | kctl "${CLUSTER_B_KUBECONFIG}" apply -f -
kctl "${CLUSTER_B_KUBECONFIG}" apply -f - <<EOF
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstanceMigration
metadata:
  name: ${VMIM_RECV}
  namespace: ${VM_NS}
spec:
  vmiName: ${VM_NAME}
  receive:
    migrationID: ${MIGRATION_ID}
EOF

log "waiting for receiver VMI (WaitingForSync) on cluster-b"
for _ in $(seq 1 60); do
  p="$(vmi_phase "${CLUSTER_B_KUBECONFIG}")"
  [ -n "${p}" ] && [ "${p}" != "Pending" ] && [ "${p}" != "Scheduling" ] && break
  sleep 5
done
log "receiver VMI phase: $(vmi_phase "${CLUSTER_B_KUBECONFIG}")"

# --- 3. connectURL + send VMIM on cluster-a ------------------------------------
CONNECT_URL="$(kctl "${CLUSTER_B_KUBECONFIG}" get kubevirt -n kubevirt kubevirt -o jsonpath='{.status.synchronizationAddresses[0]}')"
[ -n "${CONNECT_URL}" ] || die "cluster-b KubeVirt CR has no synchronizationAddresses"
log "cluster-b sync-controller address (cross-cluster pod IP): ${CONNECT_URL}"

log "creating VMIM sendTo on cluster-a"
kctl "${CLUSTER_A_KUBECONFIG}" apply -f - <<EOF
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstanceMigration
metadata:
  name: ${VMIM_SEND}
  namespace: ${VM_NS}
spec:
  vmiName: ${VM_NAME}
  sendTo:
    migrationID: ${MIGRATION_ID}
    connectURL: ${CONNECT_URL}
EOF

# --- 4. Watch the migration -----------------------------------------------------
log "watching migration (up to ${TIMEOUT_SECS}s)..."
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
last=""
result=""
while [ "$(date +%s)" -lt "${deadline}" ]; do
  sp="$(vmim_phase "${CLUSTER_A_KUBECONFIG}" "${VMIM_SEND}")"
  rp="$(vmim_phase "${CLUSTER_B_KUBECONFIG}" "${VMIM_RECV}")"
  sv="$(vmi_phase "${CLUSTER_A_KUBECONFIG}")"
  tv="$(vmi_phase "${CLUSTER_B_KUBECONFIG}")"
  state="send=${sp:--} recv=${rp:--} srcVMI=${sv:--} tgtVMI=${tv:--}"
  if [ "${state}" != "${last}" ]; then log "  ${state}"; last="${state}"; fi
  if [ "${sp}" = "Succeeded" ] && [ "${tv}" = "Running" ]; then result="ok"; break; fi
  if [ "${sp}" = "Failed" ] || [ "${rp}" = "Failed" ]; then result="failed"; break; fi
  sleep 5
done

if [ "${result}" != "ok" ]; then
  warn "migration did not complete (result=${result:-timeout}); dumping state"
  kctl "${CLUSTER_A_KUBECONFIG}" get vmim -n "${VM_NS}" "${VMIM_SEND}" -o yaml | tail -40 || true
  kctl "${CLUSTER_B_KUBECONFIG}" get vmim -n "${VM_NS}" "${VMIM_RECV}" -o yaml | tail -40 || true
  kctl "${CLUSTER_A_KUBECONFIG}" get vmi -n "${VM_NS}" -o wide || true
  kctl "${CLUSTER_B_KUBECONFIG}" get vmi -n "${VM_NS}" -o wide || true
  die "decentralized migration FAILED"
fi

TGT_IP="$(vmi_ip "${CLUSTER_B_KUBECONFIG}")"
TGT_NODE="$(vmi_node "${CLUSTER_B_KUBECONFIG}")"
log "===== migration SUCCEEDED ====="
log "VM moved: cluster-a/${SRC_NODE} (${SRC_IP}) -> cluster-b/${TGT_NODE} (${TGT_IP})"

# --- 5. Calico observations ------------------------------------------------------
log "----- Calico state after migration -----"
log "source cluster VMI/pods:"
kctl "${CLUSTER_A_KUBECONFIG}" get vmi -n "${VM_NS}" -o wide 2>/dev/null || log "  (source VMI gone)"
kctl "${CLUSTER_A_KUBECONFIG}" get pods -n "${VM_NS}" -l kubevirt.io=virt-launcher -o wide || true
log "target cluster VMI/pods:"
kctl "${CLUSTER_B_KUBECONFIG}" get vmi -n "${VM_NS}" -o wide
kctl "${CLUSTER_B_KUBECONFIG}" get pods -n "${VM_NS}" -l kubevirt.io=virt-launcher -o wide

log "ToR routes for the VM's new address (${TGT_IP}):"
docker exec "${TOR_A}" ip route get "${TGT_IP}" 2>/dev/null || true
docker exec "${TOR_B}" ip route get "${TGT_IP}" 2>/dev/null || true

log "cross-cluster reachability of the migrated VM (ping from a cluster-a pod):"
kctl "${CLUSTER_A_KUBECONFIG}" run mc-vm-pinger --image busybox --restart=Never \
  --command -- sh -c 'trap : TERM; sleep 600' >/dev/null 2>&1 || true
kctl "${CLUSTER_A_KUBECONFIG}" wait --for=condition=Ready pod/mc-vm-pinger --timeout=120s >/dev/null
if kctl "${CLUSTER_A_KUBECONFIG}" exec mc-vm-pinger -- ping -c3 -W2 "${TGT_IP}" >/dev/null 2>&1; then
  log "  PASS: migrated VM reachable at ${TGT_IP} from cluster-a"
else
  warn "  FAIL: migrated VM NOT reachable at ${TGT_IP} from cluster-a"
fi
kctl "${CLUSTER_A_KUBECONFIG}" delete pod mc-vm-pinger --ignore-not-found --wait=false >/dev/null 2>&1 || true

if [ "${CLEANUP:-false}" = "true" ]; then
  log "CLEANUP=true - removing VM/VMIMs from both clusters"
  kctl "${CLUSTER_A_KUBECONFIG}" delete vmim -n "${VM_NS}" "${VMIM_SEND}" --ignore-not-found --wait=false || true
  kctl "${CLUSTER_B_KUBECONFIG}" delete vmim -n "${VM_NS}" "${VMIM_RECV}" --ignore-not-found --wait=false || true
  kctl "${CLUSTER_A_KUBECONFIG}" delete vm "${VM_NAME}" -n "${VM_NS}" --ignore-not-found || true
  kctl "${CLUSTER_B_KUBECONFIG}" delete vm "${VM_NAME}" -n "${VM_NS}" --ignore-not-found || true
else
  log "leaving VM/VMIMs in place for inspection (CLEANUP=true to remove)"
fi

log "done."
