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

# 07-live-migrate-vm.sh — "live migrates" the migrated VM (dc0-h0-vm0) in the
# mock environment by creating a KubeVirt VirtualMachineInstanceMigration, and
# reports whether Calico preserves the pod IP across the move to a new node.
#
# This exercises the Calico KubeVirt live-migration / IP-persistence path on a
# real Calico dataplane (the target virt-launcher pod runs Calico CNI on its
# multus calico-net interface).
#
# ===========================================================================
# MOCK-SPECIFIC PREREQUISITE THIS SCRIPT HANDLES
# ===========================================================================
# KubeVirt's admission webhook refuses live migration unless every disk PVC is
# shared (ReadWriteMany) — otherwise: DisksNotLiveMigratable. The migrated VM's
# disk is an RWO local-path PVC, and local-path explicitly rejects RWX
# ("NodePath only supports ReadWriteOnce"). So real shared storage is
# unavailable on this kind cluster.
#
# Because the disk is BLANK (05 skips the real copy) and the guest is mocked,
# we stand in a static ReadWriteMany hostPath PV with NO node affinity:
#   - RWM satisfies the migratability webhook.
#   - hostPath (vs local-path's node-pinned PV) lets the migration TARGET pod
#     schedule on a different node — required for live migration.
#   - The hostPath dir is empty on each node; harmless since nothing real boots.
# This is a TEST CONVENIENCE, not how production shared storage works.
#
# Idempotent: if the disk is already an RWM static PV the rebuild is skipped;
# re-running performs another migration (to whichever node is free).
#
# Usage:
#   ./hack/test/kind/forklift/07-live-migrate-vm.sh
#
# Prerequisites:
#   - The VM exists and is running (05-hack-force-migration.sh + 06-start-migrated-vm.sh)
#   - A multi-node cluster (calico's `make kind-up` gives 4 nodes)
#
# Environment variables (all optional):
#   KUBECONFIG   kubeconfig (default: hack/test/kind/kind-kubeconfig.yaml)
#   TARGET_NS    namespace holding the VM (default: migration-target)
#   VM_NAME      VM to migrate (default: the single VM in TARGET_NS)

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../../.."; pwd)

export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/hack/test/kind/kind-kubeconfig.yaml}"

TARGET_NS="${TARGET_NS:-migration-target}"
VM_NAME="${VM_NAME:-}"

echo "=== Live-migrate migrated VM (mock) ==="
echo "  Kubeconfig: ${KUBECONFIG}"
echo "  Namespace:  ${TARGET_NS}"

# ---------------------------------------------------------------------------
# Resolve the VM.
# ---------------------------------------------------------------------------
if [ -z "${VM_NAME}" ]; then
    names=$(kubectl get vm -n "${TARGET_NS}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    count=$(printf '%s\n' "${names}" | grep -c . || true)
    [ "${count}" -eq 1 ] || { echo "  ERROR: set VM_NAME (found ${count} VMs in ${TARGET_NS})." >&2; exit 1; }
    VM_NAME="${names}"
fi
echo "  VM:         ${VM_NAME}"
echo

kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" >/dev/null 2>&1 || {
    echo "ERROR: VMI ${TARGET_NS}/${VM_NAME} not running. Run 06-start-migrated-vm.sh first." >&2
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Ensure every disk PVC is a shared (RWM) static hostPath PV. See the
#    MOCK-SPECIFIC PREREQUISITE note above.
# ---------------------------------------------------------------------------
pvcs=$(kubectl get vm "${VM_NAME}" -n "${TARGET_NS}" \
    -o jsonpath='{range .spec.template.spec.volumes[*]}{.persistentVolumeClaim.claimName}{"\n"}{end}' 2>/dev/null | grep -v '^$' || true)

needs_rebuild=""
for pvc in ${pvcs}; do
    modes=$(kubectl get pvc "${pvc}" -n "${TARGET_NS}" -o jsonpath='{.spec.accessModes}' 2>/dev/null || true)
    phase=$(kubectl get pvc "${pvc}" -n "${TARGET_NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    # Rebuild if not RWM, or if the PVC isn't healthily Bound (missing / Lost /
    # Pending — e.g. left over from an interrupted run).
    case "${modes}" in *ReadWriteMany*) ;; *) needs_rebuild="yes" ;; esac
    [ "${phase}" = "Bound" ] || needs_rebuild="yes"
done

if [ -n "${needs_rebuild}" ]; then
    echo "--- Converting disk(s) to shared RWM hostPath PVs (mock) ---"
    echo "    Stopping ${VM_NAME} (disk access mode is immutable; must recreate the PVC)."
    kubectl patch vm "${VM_NAME}" -n "${TARGET_NS}" --type merge \
        -p '{"spec":{"runStrategy":"Halted"}}' >/dev/null
    for _ in $(seq 1 30); do
        kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" >/dev/null 2>&1 || break
        sleep 3
    done

    for pvc in ${pvcs}; do
        # Preserve the PVC's labels/annotations and size as JSON (valid inline
        # YAML). NOTE: -o jsonpath='{.metadata.labels}' emits Go-map syntax
        # (map[k:v ...]), which is NOT valid YAML — use jq. The PVC may already
        # be gone (e.g. a prior interrupted run); fall back to empty/defaults.
        #
        # CRITICAL: strip ALL *.kubernetes.io/* system annotations. A bound
        # local-path PVC carries volume.kubernetes.io/storage-provisioner=
        # rancher.io/local-path (plus selected-node, bind-completed). The
        # external provisioner HONORS that annotation regardless of the PVC's
        # storageClassName, so copying it makes local-path provision a second,
        # competing PV -> ClaimMisbound -> the PVC sticks in "Lost". Keep only
        # non-system annotations (e.g. forklift.konveyor.io/disk-source).
        pvc_json=$(kubectl get pvc "${pvc}" -n "${TARGET_NS}" -o json 2>/dev/null || true)
        if [ -n "${pvc_json}" ]; then
            size=$(echo "${pvc_json}" | jq -r '.spec.resources.requests.storage // "10Gi"')
            labels=$(echo "${pvc_json}" | jq -c '(.metadata.labels // {}) | with_entries(select(.key | test("kubernetes.io/") | not))')
            anns=$(echo "${pvc_json}" | jq -c '(.metadata.annotations // {}) | with_entries(select(.key | test("kubernetes.io/") | not))')
        else
            size=10Gi; labels='{}'; anns='{}'
        fi
        pvname="${pvc}-mig-pv"

        # Bind a fresh RWM hostPath PV to the PVC. This is fiddly because:
        #   * reclaimPolicy MUST be Retain — with Delete, deleting the old PVC
        #     triggers an async delete of the same-named PV that can cascade
        #     onto the freshly recreated one, leaving the PVC stuck in the
        #     sticky "Lost" phase (which never re-binds).
        #   * the PV must be fully GONE before recreating, and observed
        #     "Available" before the PVC is created, or the PVC can bind to a
        #     stale/about-to-vanish PV.
        # Even so the bind can occasionally lose the race, so retry the whole
        # pair (nuke both, recreate) until the PVC is Bound.
        # All PVs that claimRef this PVC (jq) — there may be MORE than our
        # hostPath PV: e.g. 05's RWO local-path PV lingers with a stale claimRef
        # to the same PVC. If any of those survive, two PVs compete for the PVC
        # ("ClaimMisbound") and it ends up Lost. So clear them all.
        claiming_pvs() {
            kubectl get pv -o json 2>/dev/null | jq -r \
              ".items[] | select(.spec.claimRef.name==\"${pvc}\" and .spec.claimRef.namespace==\"${TARGET_NS}\") | .metadata.name"
        }
        bound=""
        for attempt in 1 2 3; do
            kubectl delete pvc "${pvc}" -n "${TARGET_NS}" --ignore-not-found --wait=true >/dev/null 2>&1 || true
            for v in $(claiming_pvs); do
                kubectl delete pv "${v}" --ignore-not-found --wait=true >/dev/null 2>&1 || true
            done
            # Wait until the PVC is gone AND no PV still claims it.
            for _ in $(seq 1 30); do
                if ! kubectl get pvc "${pvc}" -n "${TARGET_NS}" >/dev/null 2>&1 && [ -z "$(claiming_pvs)" ]; then
                    break
                fi
                sleep 1
            done

            kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${pvname}
spec:
  capacity: {storage: ${size}}
  accessModes: [ReadWriteMany]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: forklift-mock-shared
  hostPath: {path: /var/lib/forklift-mock-disks/${pvc}, type: DirectoryOrCreate}
  claimRef: {namespace: ${TARGET_NS}, name: ${pvc}}
EOF
            # Wait until the PV is observed Available (controller has it cached)
            # before creating the PVC.
            for _ in $(seq 1 15); do
                [ "$(kubectl get pv "${pvname}" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Available" ] && break
                sleep 1
            done

            kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${pvc}
  namespace: ${TARGET_NS}
  labels: ${labels}
  annotations: ${anns}
spec:
  accessModes: [ReadWriteMany]
  volumeMode: Filesystem
  storageClassName: forklift-mock-shared
  volumeName: ${pvname}
  resources: {requests: {storage: ${size}}}
EOF
            for _ in $(seq 1 15); do
                phase=$(kubectl get pvc "${pvc}" -n "${TARGET_NS}" -o jsonpath='{.status.phase}' 2>/dev/null)
                [ "${phase}" = "Bound" ] && { bound=yes; break; }
                [ "${phase}" = "Lost" ] && break
                sleep 2
            done
            [ -n "${bound}" ] && break
            echo "    ${pvc}: bind attempt ${attempt} -> ${phase:-Pending}, retrying"
        done
        echo "    ${pvc} -> ${pvname} ($(kubectl get pvc "${pvc}" -n "${TARGET_NS}" -o jsonpath='{.status.phase}' 2>/dev/null))"
        [ -n "${bound}" ] || { echo "ERROR: could not bind ${pvc} after retries." >&2; exit 1; }
    done

    echo "    Starting ${VM_NAME} ..."
    kubectl patch vm "${VM_NAME}" -n "${TARGET_NS}" --type merge \
        -p '{"spec":{"runStrategy":"Always"}}' >/dev/null
else
    echo "--- Disk(s) already shared (RWM); ensuring VM is started ---"
    kubectl patch vm "${VM_NAME}" -n "${TARGET_NS}" --type merge \
        -p '{"spec":{"runStrategy":"Always"}}' >/dev/null
fi

echo "--- Waiting for VMI Running + LiveMigratable ---"
for _ in $(seq 1 45); do
    phase=$(kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    lm=$(kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" \
        -o jsonpath='{range .status.conditions[?(@.type=="LiveMigratable")]}{.status}{end}' 2>/dev/null || true)
    [ "${phase}" = "Running" ] && [ "${lm}" = "True" ] && break
    sleep 4
done
if [ "${phase:-}" != "Running" ] || [ "${lm:-}" != "True" ]; then
    echo "  ERROR: VMI not Running+LiveMigratable (phase=${phase:-} LiveMigratable=${lm:-})." >&2
    kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" \
        -o jsonpath='{range .status.conditions[*]}    {.type}={.status} {.reason} {.message}{"\n"}{end}' >&2
    exit 1
fi

src_node=$(kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" -o jsonpath='{.status.nodeName}' 2>/dev/null)
src_ip=$(kubectl get pod -n "${TARGET_NS}" -l kubevirt.io=virt-launcher \
    -o jsonpath='{.items[0].metadata.annotations.cni\.projectcalico\.org/podIP}' 2>/dev/null)
echo "  VMI Running on ${src_node}, Calico IP ${src_ip}, LiveMigratable=True."
echo

# ---------------------------------------------------------------------------
# 2. Trigger the live migration. Reuse an in-flight VMIM if present; else
#    create a new one (re-running migrates again).
# ---------------------------------------------------------------------------
active=$(kubectl get vmim -n "${TARGET_NS}" \
    -o jsonpath="{range .items[?(@.spec.vmiName==\"${VM_NAME}\")]}{.metadata.name} {.status.phase}{\"\n\"}{end}" 2>/dev/null \
    | awk '$2!="Succeeded" && $2!="Failed" {print $1; exit}')
if [ -n "${active}" ]; then
    echo "--- Reusing in-flight migration ${active} ---"
else
    echo "--- Creating VirtualMachineInstanceMigration ---"
    kubectl create -f - <<EOF
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstanceMigration
metadata:
  generateName: lm-${VM_NAME}-
  namespace: ${TARGET_NS}
spec:
  vmiName: ${VM_NAME}
EOF
fi
echo

# ---------------------------------------------------------------------------
# 3. Watch to completion.
# ---------------------------------------------------------------------------
echo "--- Watching migration ---"
for _ in $(seq 1 60); do
    mp=$(kubectl get vmim -n "${TARGET_NS}" \
        -o jsonpath="{range .items[?(@.spec.vmiName==\"${VM_NAME}\")]}{.status.phase}{\"\n\"}{end}" 2>/dev/null | tail -1)
    node=$(kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" -o jsonpath='{.status.nodeName}' 2>/dev/null)
    echo "    phase=${mp:-<>} vmiNode=${node}"
    { [ "${mp}" = "Succeeded" ] || [ "${mp}" = "Failed" ]; } && break
    sleep 4
done
echo

# ---------------------------------------------------------------------------
# 4. Report — including the IP-persistence check Calico cares about.
# ---------------------------------------------------------------------------
echo "=== Result ==="
dst_node=$(kubectl get vmi "${VM_NAME}" -n "${TARGET_NS}" -o jsonpath='{.status.nodeName}' 2>/dev/null)
dst_ip=$(kubectl get pod -n "${TARGET_NS}" -l kubevirt.io=virt-launcher --field-selector status.phase=Running \
    -o jsonpath='{.items[-1].metadata.annotations.cni\.projectcalico\.org/podIP}' 2>/dev/null)
echo "  migration phase: ${mp:-unknown}"
echo "  node:            ${src_node} -> ${dst_node}"
echo "  Calico pod IP:   ${src_ip} -> ${dst_ip:-?}"
if [ -n "${dst_ip}" ] && [ "${src_ip}" = "${dst_ip}" ] && [ "${src_node}" != "${dst_node}" ]; then
    echo "  ✓ IP preserved across live migration to a new node."
elif [ "${mp:-}" = "Succeeded" ]; then
    echo "  (migration Succeeded; compare IPs above)"
fi
echo
kubectl get vmim,vmi -n "${TARGET_NS}" 2>/dev/null
