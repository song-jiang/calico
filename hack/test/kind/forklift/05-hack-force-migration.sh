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

# 05-hack-force-migration.sh — drives a Forklift vSphere→KubeVirt
# migration against vcsim all the way to a created destination VirtualMachine,
# WITHOUT copying any disk data (vcsim has no disk data plane — see the sibling
# 04-create-migration-crs.sh, which stops at validation).
#
# This is useful for exercising the destination *build* path — in particular
# the Calico L2 NIC annotations the vSphere Builder stamps onto the VM template
# (cni.projectcalico.org/<iface>.hwAddr) — end to end on a real cluster.
#
# HOW THE DISK COPY IS SKIPPED
#   Forklift's "conversion-only" itinerary (Plan.Spec.Type: conversion) omits
#   the CreateDataVolumes/CopyDisks phases entirely; with skipGuestConversion
#   it also drops the virt-v2v conversion pod (the RequiresConversion predicate
#   becomes false). The pipeline collapses to:
#       Started -> StorePowerState -> PowerOffSource -> WaitForPowerOff
#                -> CreateVM -> Completed
#   Every phase is control-plane (vcsim handles power ops) plus CreateVM. The
#   destination VirtualMachine is built from inventory + pre-created PVCs.
#
# GATES THIS SCRIPT CLEARS (all verified against the Forklift source)
#   * GuestToolsIssue   — fires only for a powered-ON VM without VMware Tools
#                         (validator.go GuestToolsInstalled). We power the VM
#                         off in vcsim first.
#   * MigrationOnlyConversion requires a PVC per disk, matched by labels
#     vmID/vmUUID (validation.go getVmPVCs, kubevirt.go getPVCs). We pre-create
#     blank PVCs with those labels and a forklift.konveyor.io/disk-source
#     annotation = the disk backing file (so builder.go mapDisks matches them).
#   * The migration's PhaseStarted cleanup deletes those PVCs once (it assumes a
#     storage populator will recreate them). We have no populator, so we
#     re-assert the PVCs every ~2s through the brief power-off window until
#     CreateVM has consumed them — see apply_pvcs() below.
#   * skipGuestConversion requires a VDDK init image, validated by a Job that
#     runs `file -E /opt/vmware-vix-disklib-distrib/lib64/libvixDiskLib.so`
#     (validation.go). We build a tiny FAKE VDDK image that only deposits that
#     placeholder file — enough to pass validation. It does NOT contain real
#     VDDK libraries; a real disk transfer would still fail.
#
# Idempotent: existing resources are skipped / re-applied.
#
# Usage:
#   ./hack/test/kind/forklift/05-hack-force-migration.sh
#
# Prerequisites:
#   - KIND cluster with Calico, MockVirt, and Forklift deployed
#   - vcsim running (01-deploy-forklift-prereqs.sh)
#   - CDI StorageProfile configured (02-configure-forklift-storage.sh)
#   - Forklift operator + controller deployed (03-deploy-forklift.sh)
#   - docker, jq, and the local kind-registry (for the fake VDDK image)
#
# Environment variables (all optional):
#   KUBECONFIG       kubeconfig (default: hack/test/kind/kind-kubeconfig.yaml)
#   FORKLIFT_NS      Forklift namespace (default: konveyor-forklift)
#   TARGET_NS        namespace for the migrated VM (default: migration-target)
#   VCSIM_URL        vcsim SDK URL (default: https://vcsim.default.svc:8989/sdk)
#   VCSIM_USER/VCSIM_PASSWORD  vcsim creds (default: user/pass)
#   VM_NAME          vcsim VM to migrate (default: DC0_H0_VM0)
#   VM_ID/VM_UUID/NETWORK_ID/DATASTORE_ID  discovered from vcsim if unset
#   STORAGE_CLASS    target StorageClass (default: standard)
#   VLAN_ID/VLAN_SUBNET  Calico l2Bridge VLAN (default: 100 / 10.244.0.0/16)
#   FAKE_VDDK_IMAGE  fake VDDK init image ref
#                    (default: localhost:5000/projectalexo/fake-vddk:dev)
#   GOVC_IMAGE       govc container image (default: vmware/govc:latest)

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../../.."; pwd)

export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/hack/test/kind/kind-kubeconfig.yaml}"

FORKLIFT_NS="${FORKLIFT_NS:-konveyor-forklift}"
TARGET_NS="${TARGET_NS:-migration-target}"
VCSIM_URL="${VCSIM_URL:-https://vcsim.default.svc:8989/sdk}"
VCSIM_USER="${VCSIM_USER:-user}"
VCSIM_PASSWORD="${VCSIM_PASSWORD:-pass}"
VM_NAME="${VM_NAME:-DC0_H0_VM0}"
STORAGE_CLASS="${STORAGE_CLASS:-standard}"
VLAN_ID="${VLAN_ID:-100}"
VLAN_SUBNET="${VLAN_SUBNET:-10.244.0.0/16}"
FAKE_VDDK_IMAGE="${FAKE_VDDK_IMAGE:-localhost:5000/projectalexo/fake-vddk:dev}"
GOVC_IMAGE="${GOVC_IMAGE:-vmware/govc:latest}"

# Resource names.
PROVIDER=vsphere-vcsim
SECRET=vsphere-vcsim
NETMAP=vcsim-calico-netmap
STORMAP=vcsim-storagemap
PLAN=vcsim-conversion-plan
MIGRATION=vcsim-conversion-migration
NAD=calico-net

echo "=== Forklift vSphere->KubeVirt VM creation (no disk copy) ==="
echo "  Kubeconfig:   ${KUBECONFIG}"
echo "  Forklift NS:  ${FORKLIFT_NS}"
echo "  Target NS:    ${TARGET_NS}"
echo "  VM:           ${VM_NAME}"
echo "  Fake VDDK:    ${FAKE_VDDK_IMAGE}"
echo

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PF_PID=""
cleanup() { [ -n "${PF_PID}" ] && kill "${PF_PID}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

skip_if_exists() {
    local resource=$1 name=$2 ns=${3:-}
    local ns_flag=""
    [ -n "${ns}" ] && ns_flag="-n ${ns}"
    # shellcheck disable=SC2086
    kubectl get "${resource}" ${ns_flag} "${name}" >/dev/null 2>&1
}

wait_for_condition() {
    local resource=$1 name=$2 condition=$3 ns=${4:-}
    local ns_flag=""
    [ -n "${ns}" ] && ns_flag="-n ${ns}"
    echo "  Waiting for ${resource}/${name} ${condition} ..."
    local retries=60
    while [ $retries -gt 0 ]; do
        # shellcheck disable=SC2086
        local val
        val=$(kubectl get "${resource}" ${ns_flag} "${name}" \
            -o jsonpath="{.status.conditions[?(@.type==\"${condition}\")].status}" 2>/dev/null || true)
        [ "${val}" = "True" ] && return 0
        retries=$((retries - 1)); sleep 5
    done
    echo "  ERROR: timed out waiting for ${resource}/${name} ${condition}"
    return 1
}

# govc against vcsim via a host port-forward + the govc container.
GOVC() { docker run --rm --network host --entrypoint /govc \
    -e GOVC_URL="https://${VCSIM_USER}:${VCSIM_PASSWORD}@127.0.0.1:18989/sdk" \
    -e GOVC_INSECURE=1 "${GOVC_IMAGE}" "$@"; }

# ---------------------------------------------------------------------------
# 0. Ensure the fake VDDK image exists in the registry.
# ---------------------------------------------------------------------------
echo "--- Fake VDDK image ---"
reg_host="${FAKE_VDDK_IMAGE%%/*}"
reg_path="${FAKE_VDDK_IMAGE#*/}"; reg_repo="${reg_path%:*}"; reg_tag="${reg_path##*:}"
if curl -fs "http://${reg_host}/v2/${reg_repo}/tags/list" 2>/dev/null | grep -q "\"${reg_tag}\""; then
    echo "  Already in registry, skipping build."
else
    tmpdir=$(mktemp -d)
    cat > "${tmpdir}/Containerfile" <<'EOF'
# Fake VDDK init image for vcsim testing ONLY — no real VMware libraries.
# Deposits a placeholder libvixDiskLib.so so Forklift's VDDK validation Job
# (`file -E /opt/vmware-vix-disklib-distrib/lib64/libvixDiskLib.so`) passes.
FROM busybox
RUN mkdir -p /vmware-vix-disklib-distrib/lib64 \
 && echo "fake-vddk-placeholder" > /vmware-vix-disklib-distrib/lib64/libvixDiskLib.so \
 && mkdir -p /opt
ENTRYPOINT ["cp", "-r", "/vmware-vix-disklib-distrib", "/opt"]
EOF
    docker build -t "${FAKE_VDDK_IMAGE}" -f "${tmpdir}/Containerfile" "${tmpdir}" >/dev/null
    docker push "${FAKE_VDDK_IMAGE}" >/dev/null
    rm -rf "${tmpdir}"
    echo "  Built and pushed ${FAKE_VDDK_IMAGE}."
fi
echo

# ---------------------------------------------------------------------------
# 1. Discover VM identity from vcsim and power the VM off.
# ---------------------------------------------------------------------------
echo "--- Discover vcsim inventory ---"
kubectl port-forward -n default svc/vcsim 18989:8989 >/tmp/vcsim-pf.log 2>&1 &
PF_PID=$!
until grep -q 'Forwarding from' /tmp/vcsim-pf.log 2>/dev/null; do sleep 1; done

VM_ID="${VM_ID:-$(GOVC ls -i "/DC0/vm/${VM_NAME}" | cut -d: -f2)}"
VM_UUID="${VM_UUID:-$(GOVC object.collect -s "/DC0/vm/${VM_NAME}" config.uuid)}"
NETWORK_ID="${NETWORK_ID:-$(GOVC device.info -json -vm "${VM_NAME}" 'ethernet-*' \
    | jq -r '.devices[0].backing.port.portgroupKey // .devices[0].backing.network.value // empty')}"
DATASTORE_ID="${DATASTORE_ID:-$(GOVC ls -i "/DC0/datastore/LocalDS_0" | cut -d: -f2)}"

# Disks: TAB-separated "backingFile<TAB>capacityKB" lines.
DISKS=$(GOVC device.info -json -vm "${VM_NAME}" 'disk-*' \
    | jq -r '.devices[] | select(.capacityInKB != null) | "\(.backing.fileName)\t\(.capacityInKB)"')
DISK_COUNT=$(printf '%s\n' "${DISKS}" | grep -c . || true)

echo "  VM_ID=${VM_ID}  VM_UUID=${VM_UUID}"
echo "  NETWORK_ID=${NETWORK_ID}  DATASTORE_ID=${DATASTORE_ID}  DISKS=${DISK_COUNT}"

POWER=$(GOVC object.collect -s "/DC0/vm/${VM_NAME}" runtime.powerState)
if [ "${POWER}" = "poweredOn" ]; then
    echo "  Powering off ${VM_NAME} (clears GuestToolsIssue) ..."
    GOVC vm.power -off "${VM_NAME}" >/dev/null
fi
echo

# ---------------------------------------------------------------------------
# 2. Valid Calico Network + IPPool + NAD (so CalicoIssues passes and the
#    Builder stamps the Calico NIC annotation).
# ---------------------------------------------------------------------------
echo "--- Calico Network CRD / Network / IPPool ---"
if ! skip_if_exists crd networks.projectcalico.org; then
    kubectl apply -f - <<'EOF'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: networks.projectcalico.org
spec:
  group: projectcalico.org
  names: {kind: Network, listKind: NetworkList, plural: networks, singular: network}
  scope: Cluster
  versions:
  - name: v3
    served: true
    storage: true
    subresources: {status: {}}
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            x-kubernetes-preserve-unknown-fields: true
          status:
            type: object
            x-kubernetes-preserve-unknown-fields: true
EOF
fi
kubectl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: Network
metadata:
  name: default
spec:
  l2Bridge:
    vlans:
    - vlan: {id: ${VLAN_ID}}
      subnets:
      - cidr: "${VLAN_SUBNET}"
EOF
kubectl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: migration-pool
spec:
  cidr: ${VLAN_SUBNET}
  ipipMode: Never
  vxlanMode: Never
  natOutgoing: false
  disabled: true
EOF
echo

echo "--- Target namespace + Calico NAD ---"
kubectl create namespace "${TARGET_NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -f - <<EOF
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: ${NAD}
  namespace: ${TARGET_NS}
spec:
  config: |
    {"cniVersion":"0.3.1","type":"calico","policy":{"type":"k8s"},"datastore_type":"kubernetes","kubernetes":{"k8s_api_root":"https://10.96.0.1:443","kubeconfig":"/etc/cni/net.d/calico-kubeconfig"},"network":"default","ipam":{"type":"calico-ipam"}}
EOF
echo

# ---------------------------------------------------------------------------
# 3. vSphere Provider (fake VDDK image set) + Secret.
# ---------------------------------------------------------------------------
echo "--- vSphere Provider ---"
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${SECRET}
  namespace: ${FORKLIFT_NS}
  labels:
    createdForResourceType: providers
    createdForResource: ${PROVIDER}
    createdForProviderType: vsphere
type: Opaque
stringData:
  user: "${VCSIM_USER}"
  password: "${VCSIM_PASSWORD}"
  thumbprint: ""
  insecureSkipVerify: "true"
EOF
kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: Provider
metadata:
  name: ${PROVIDER}
  namespace: ${FORKLIFT_NS}
spec:
  type: vsphere
  url: ${VCSIM_URL}
  secret:
    name: ${SECRET}
    namespace: ${FORKLIFT_NS}
  settings:
    vddkInitImage: "${FAKE_VDDK_IMAGE}"
    sdkEndpoint: vcenter
EOF
wait_for_condition provider "${PROVIDER}" Ready "${FORKLIFT_NS}"
echo "  Provider Ready."
echo

# ---------------------------------------------------------------------------
# 4. NetworkMap (-> Calico multus NAD) and StorageMap.
# ---------------------------------------------------------------------------
echo "--- NetworkMap + StorageMap ---"
kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: NetworkMap
metadata:
  name: ${NETMAP}
  namespace: ${FORKLIFT_NS}
spec:
  provider:
    source: {name: ${PROVIDER}, namespace: ${FORKLIFT_NS}}
    destination: {name: host, namespace: ${FORKLIFT_NS}}
  map:
  - source: {id: ${NETWORK_ID}}
    destination: {type: multus, name: ${NAD}, namespace: ${TARGET_NS}}
EOF
kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: StorageMap
metadata:
  name: ${STORMAP}
  namespace: ${FORKLIFT_NS}
spec:
  provider:
    source: {name: ${PROVIDER}, namespace: ${FORKLIFT_NS}}
    destination: {name: host, namespace: ${FORKLIFT_NS}}
  map:
  - source: {id: ${DATASTORE_ID}}
    destination:
      storageClass: ${STORAGE_CLASS}
      accessMode: ReadWriteOnce
      volumeMode: Filesystem
EOF
wait_for_condition networkmap "${NETMAP}" Ready "${FORKLIFT_NS}"
wait_for_condition storagemap "${STORMAP}" Ready "${FORKLIFT_NS}"
echo "  Maps Ready."
echo

# ---------------------------------------------------------------------------
# 5. Pre-create one blank PVC per disk, labeled/annotated so Forklift adopts
#    them (getVmPVCs validation + getPVCs build + mapDisks matching).
#
# apply_pvcs() is also re-invoked during the migration (below): the migration's
# PhaseStarted cleanup deletes these PVCs once (DeletePopulatedPVCs uses the same
# vmID/vmUUID selector), assuming a populator will recreate them. We have no
# populator, so we re-assert them ourselves through the short power-off window
# until CreateVM has consumed them.
# ---------------------------------------------------------------------------
apply_pvcs() {
    local quiet=${1:-}
    local i=0 file capkb gib pvc_name
    while IFS=$'\t' read -r file capkb; do
        [ -z "${file}" ] && continue
        # Round capacity up to whole GiB (1 GiB = 1048576 KiB).
        gib=$(awk -v k="${capkb}" 'BEGIN{print int((k+1048575)/1048576)}')
        [ "${gib}" -lt 1 ] && gib=1
        pvc_name="vcsim-${VM_ID}-disk-${i}"
        kubectl apply -f - >/dev/null 2>&1 <<EOF || true
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${pvc_name}
  namespace: ${TARGET_NS}
  labels:
    vmID: "${VM_ID}"
    vmUUID: "${VM_UUID}"
  annotations:
    forklift.konveyor.io/disk-source: "${file}"
spec:
  accessModes: [ReadWriteOnce]
  volumeMode: Filesystem
  storageClassName: ${STORAGE_CLASS}
  resources:
    requests:
      storage: ${gib}Gi
EOF
        [ -z "${quiet}" ] && echo "  PVC ${pvc_name} (${gib}Gi) <- ${file}"
        i=$((i + 1))
    done <<< "${DISKS}"
}

echo "--- Pre-create disk PVCs ---"
apply_pvcs
echo

# ---------------------------------------------------------------------------
# 6. Conversion-only Plan with skipGuestConversion.
# ---------------------------------------------------------------------------
echo "--- Plan (type: conversion, skipGuestConversion: true) ---"
kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: Plan
metadata:
  name: ${PLAN}
  namespace: ${FORKLIFT_NS}
spec:
  type: conversion
  skipGuestConversion: true
  provider:
    source: {name: ${PROVIDER}, namespace: ${FORKLIFT_NS}}
    destination: {name: host, namespace: ${FORKLIFT_NS}}
  map:
    network: {name: ${NETMAP}, namespace: ${FORKLIFT_NS}}
    storage: {name: ${STORMAP}, namespace: ${FORKLIFT_NS}}
  targetNamespace: ${TARGET_NS}
  vms:
  - id: ${VM_ID}
    name: ${VM_NAME}
EOF

echo "  Plan conditions:"
kubectl get plan "${PLAN}" -n "${FORKLIFT_NS}" \
    -o jsonpath='{range .status.conditions[*]}    {.type}: {.status} ({.category}) {.message}{"\n"}{end}' 2>/dev/null || true

if ! wait_for_condition plan "${PLAN}" Ready "${FORKLIFT_NS}"; then
    echo
    echo "  Plan did not reach Ready. Conditions:"
    kubectl get plan "${PLAN}" -n "${FORKLIFT_NS}" \
        -o jsonpath='{range .status.conditions[*]}    {.type}: {.status} ({.category}) {.message}{"\n"}{end}'
    exit 1
fi
echo "  Plan Ready."
echo

# ---------------------------------------------------------------------------
# 7. Migration — runs to CreateVM/Completed (no disk data moves).
# ---------------------------------------------------------------------------
echo "--- Migration ---"
kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: Migration
metadata:
  name: ${MIGRATION}
  namespace: ${FORKLIFT_NS}
spec:
  plan: {name: ${PLAN}, namespace: ${FORKLIFT_NS}}
EOF

# Re-assert the PVCs every couple of seconds (they're deleted once at
# PhaseStarted) and stop as soon as the VirtualMachine appears. Success is the
# VM object existing, not a phase string — the per-VM phase flickers through
# CreateVM->Completed quickly.
echo "  Re-asserting PVCs through power-off window, waiting for the VM ..."
retries=60
vm_obj=""
while [ $retries -gt 0 ]; do
    apply_pvcs quiet
    vm_obj=$(kubectl get virtualmachine -n "${TARGET_NS}" -o name 2>/dev/null | head -n1)
    phase=$(kubectl get plan "${PLAN}" -n "${FORKLIFT_NS}" \
        -o jsonpath='{.status.migration.vms[0].phase}' 2>/dev/null || true)
    echo "    VM phase: ${phase:-<none>}  vm: ${vm_obj:-none}"
    [ -n "${vm_obj}" ] && break
    err=$(kubectl get plan "${PLAN}" -n "${FORKLIFT_NS}" \
        -o jsonpath='{.status.migration.vms[0].error.phase}' 2>/dev/null || true)
    if [ -n "${err}" ]; then
        echo "  Migration error at phase ${err}:"
        kubectl get plan "${PLAN}" -n "${FORKLIFT_NS}" \
            -o jsonpath='{.status.migration.vms[0].error.reasons}' ; echo
        break
    fi
    retries=$((retries - 1)); sleep 2
done
echo

# ---------------------------------------------------------------------------
# 8. Verify the destination VirtualMachine + its Calico NIC annotations.
# ---------------------------------------------------------------------------
echo "=== Result ==="
[ -z "${vm_obj}" ] && vm_obj=$(kubectl get virtualmachine -n "${TARGET_NS}" -o name 2>/dev/null | head -n1)
if [ -z "${vm_obj}" ]; then
    echo "  No VirtualMachine created in ${TARGET_NS}."
    echo "  Inspect: kubectl get plan ${PLAN} -n ${FORKLIFT_NS} -o yaml"
    exit 1
fi
echo "  Created ${vm_obj} in ${TARGET_NS}"
echo "  Calico NIC annotations stamped by the Builder on the VM template:"
calico_anns=$(kubectl get -n "${TARGET_NS}" "${vm_obj}" \
    -o jsonpath='{.spec.template.metadata.annotations}' 2>/dev/null \
    | jq -r 'to_entries[] | select(.key|test("calico")) | "    \(.key) = \(.value)"')
if [ -n "${calico_anns}" ]; then
    echo "${calico_anns}"
else
    echo "    (none found — check the NetworkMap targets the Calico multus NAD)"
fi
echo
echo "Done. Clean up with:"
echo "  kubectl delete migration,plan,networkmap,storagemap,provider,secret -n ${FORKLIFT_NS} \\"
echo "    ${MIGRATION} ${PLAN} ${NETMAP} ${STORMAP} ${PROVIDER} ${SECRET} 2>/dev/null"
echo "  kubectl delete ns ${TARGET_NS}; kubectl delete network.projectcalico.org default; \\"
echo "  kubectl delete ippool.projectcalico.org migration-pool"
