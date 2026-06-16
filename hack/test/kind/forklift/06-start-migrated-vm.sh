#!/bin/bash
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

# 06-start-migrated-vm.sh — starts the VirtualMachine created by
# 05-hack-force-migration.sh and reports what Calico does with it.
#
# WHY START IT
#   Starting the VM is how the Calico CNI path gets exercised end to end:
#   KubeVirt creates a VirtualMachineInstance -> a virt-launcher pod -> whose
#   multus calico-net interface triggers a Calico CNI ADD that consumes the
#   cni.projectcalico.org/<iface>.hwAddr annotation the Forklift Builder
#   stamped on the VM template, and requests an IP from the Calico IPPool.
#   That CNI consumption is the one thing the in-repo unit tests cannot cover.
#
# WHAT IT WON'T DO
#   The disk PVC is blank (05 skips the real disk copy — vcsim has no disk
#   data), and this cluster runs KubeVirt in MockVirt mode, so no real guest OS
#   boots. The value here is the pod-networking / Calico IPAM path, not a
#   functioning guest.
#
# Idempotent: re-running just re-asserts runStrategy=Always and re-reports
# status; starting an already-started VM is a no-op.
#
# Usage:
#   ./hack/test/kind/forklift/06-start-migrated-vm.sh
#
# Environment variables (all optional):
#   KUBECONFIG   kubeconfig (default: hack/test/kind/kind-kubeconfig.yaml)
#   TARGET_NS    namespace holding the migrated VM (default: migration-target)
#   VM_NAME      VM to start (default: the single VM in TARGET_NS)

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../../.."; pwd)

export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/hack/test/kind/kind-kubeconfig.yaml}"

TARGET_NS="${TARGET_NS:-migration-target}"
VM_NAME="${VM_NAME:-}"

echo "=== Start migrated VM ==="
echo "  Kubeconfig: ${KUBECONFIG}"
echo "  Namespace:  ${TARGET_NS}"

# ---------------------------------------------------------------------------
# Resolve the VM (default: the single VM in TARGET_NS).
# ---------------------------------------------------------------------------
if [ -z "${VM_NAME}" ]; then
    names=$(kubectl get vm -n "${TARGET_NS}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    count=$(printf '%s\n' "${names}" | grep -c . || true)
    if [ "${count}" -eq 0 ]; then
        echo "  ERROR: no VirtualMachine found in ${TARGET_NS}." >&2
        echo "         Run 05-hack-force-migration.sh first." >&2
        exit 1
    elif [ "${count}" -gt 1 ]; then
        echo "  ERROR: multiple VMs in ${TARGET_NS}; set VM_NAME to one of:" >&2
        printf '           %s\n' ${names} >&2
        exit 1
    fi
    VM_NAME="${names}"
fi
echo "  VM:         ${VM_NAME}"
echo

if ! kubectl get vm "${VM_NAME}" -n "${TARGET_NS}" >/dev/null 2>&1; then
    echo "ERROR: VirtualMachine ${TARGET_NS}/${VM_NAME} not found." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Start it (idempotent). The VM uses runStrategy, so set runStrategy=Always
# rather than spec.running (the two are mutually exclusive).
# ---------------------------------------------------------------------------
current=$(kubectl get vm "${VM_NAME}" -n "${TARGET_NS}" -o jsonpath='{.spec.runStrategy}' 2>/dev/null || true)
if [ "${current}" = "Always" ]; then
    echo "--- runStrategy already Always (no change) ---"
else
    echo "--- Setting runStrategy=Always (was: ${current:-<unset>}) ---"
    kubectl patch vm "${VM_NAME}" -n "${TARGET_NS}" --type merge \
        -p '{"spec":{"runStrategy":"Always"}}'
fi
echo

# ---------------------------------------------------------------------------
# Wait (bounded) for the VMI and virt-launcher pod, then report — including
# whatever Calico assigned. Does not fail if the guest never reaches Running
# (expected on MockVirt with a blank disk); the networking path is the point.
# ---------------------------------------------------------------------------
echo "--- Waiting for VMI / virt-launcher pod (up to ~90s) ---"
for _ in $(seq 1 45); do
    vmi_phase=$(kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" \
        -o jsonpath='{.status.phase}' 2>/dev/null || true)
    pod=$(kubectl get pod -n "${TARGET_NS}" -l kubevirt.io=virt-launcher \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    echo "    VMI phase: ${vmi_phase:-<pending>}  launcher: ${pod:-<none>}"
    [ "${vmi_phase}" = "Running" ] && break
    [ "${vmi_phase}" = "Failed" ] && break
    sleep 2
done
echo

echo "=== Result ==="
kubectl get vm,vmi -n "${TARGET_NS}" 2>/dev/null
echo
pod=$(kubectl get pod -n "${TARGET_NS}" -l kubevirt.io=virt-launcher \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -n "${pod}" ]; then
    echo "virt-launcher pod: ${pod}"
    echo "  status:  $(kubectl get pod "${pod}" -n "${TARGET_NS}" -o jsonpath='{.status.phase}' 2>/dev/null)"
    echo "  Calico-preserved MAC (from VM template):"
    kubectl get vm "${VM_NAME}" -n "${TARGET_NS}" \
        -o jsonpath='{.spec.template.metadata.annotations}' 2>/dev/null \
        | jq -r 'to_entries[] | select(.key|test("calico")) | "    \(.key) = \(.value)"' 2>/dev/null || true
    echo "  Calico-assigned pod IPs (from CNI):"
    ips=$(kubectl get pod "${pod}" -n "${TARGET_NS}" \
        -o jsonpath='{.metadata.annotations.cni\.projectcalico\.org/podIPs}' 2>/dev/null || true)
    echo "    ${ips:-<not assigned yet>}"
else
    echo "No virt-launcher pod yet. Inspect with:"
    echo "  kubectl describe vmi ${VM_NAME} -n ${TARGET_NS}"
fi
echo
echo "Stop the VM again with:"
echo "  kubectl patch vm ${VM_NAME} -n ${TARGET_NS} --type merge -p '{\"spec\":{\"runStrategy\":\"Halted\"}}'"
