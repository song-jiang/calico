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

# 04-create-migration-crs.sh — creates Forklift resources to simulate a
# vSphere-to-KubeVirt cold migration using vcsim and a Calico L2 bridge NAD.
#
# This script creates:
#   1. Calico Network CRD (projectcalico.org/v3 Network with l2Bridge)
#   2. Calico Network CR and IPPool for VLAN subnet
#   3. Target namespace and Calico NetworkAttachmentDefinition
#   4. vSphere Provider (pointing at vcsim)
#   5. NetworkMap and StorageMap
#   6. Migration Plan (cold migration)
#   7. Migration (triggers the plan)
#
# Every step is idempotent — already-existing resources are skipped.
#
# Usage:
#   ./hack/test/kind/forklift/04-create-migration-crs.sh
#
# Prerequisites:
#   - A KIND cluster with Calico, MockVirt, and Forklift deployed
#   - vcsim running (see 01-deploy-forklift-prereqs.sh)
#   - Forklift operator + controller deployed (03-deploy-forklift.sh)
#   - kubectl configured to talk to the cluster
#
# Environment variables (all optional):
#   KUBECONFIG          Path to kubeconfig (default: hack/test/kind/kind-kubeconfig.yaml)
#   FORKLIFT_NS         Forklift operator namespace (default: konveyor-forklift)
#   TARGET_NS           Namespace for migrated VMs (default: migration-target)
#   VCSIM_URL           vcsim SDK URL (default: https://vcsim.default.svc:8989/sdk)
#   VCSIM_USER          vcsim username (default: user)
#   VCSIM_PASSWORD      vcsim password (default: pass)
#   VLAN_SUBNET         Subnet CIDR for the Calico VLAN (default: 10.244.0.0/16)
#   VLAN_ID             VLAN ID for the l2Bridge entry (default: 100)
#   VM_ID               vcsim VM managed object ID to migrate (default: vm-62)
#   VM_NAME             vcsim VM name (default: DC0_H0_VM0)
#   NETWORK_ID          vcsim network managed object ID (default: dvportgroup-12)
#   DATASTORE_ID        vcsim datastore managed object ID (default: datastore-59)
#   STORAGE_CLASS       Target StorageClass (default: standard)

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../../.."; pwd)

export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/hack/test/kind/kind-kubeconfig.yaml}"

FORKLIFT_NS="${FORKLIFT_NS:-konveyor-forklift}"
TARGET_NS="${TARGET_NS:-migration-target}"
VCSIM_URL="${VCSIM_URL:-https://vcsim.default.svc:8989/sdk}"
VCSIM_USER="${VCSIM_USER:-user}"
VCSIM_PASSWORD="${VCSIM_PASSWORD:-pass}"
VLAN_SUBNET="${VLAN_SUBNET:-10.244.0.0/16}"
VLAN_ID="${VLAN_ID:-100}"
VM_ID="${VM_ID:-vm-62}"
VM_NAME="${VM_NAME:-DC0_H0_VM0}"
NETWORK_ID="${NETWORK_ID:-dvportgroup-12}"
DATASTORE_ID="${DATASTORE_ID:-datastore-59}"
STORAGE_CLASS="${STORAGE_CLASS:-standard}"

echo "=== Simulate Forklift vSphere-to-KubeVirt migration ==="
echo "  Kubeconfig:     ${KUBECONFIG}"
echo "  Forklift NS:    ${FORKLIFT_NS}"
echo "  Target NS:      ${TARGET_NS}"
echo "  vcsim URL:      ${VCSIM_URL}"
echo "  VM to migrate:  ${VM_NAME} (${VM_ID})"
echo

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
skip_if_exists() {
    local resource=$1 name=$2 ns=${3:-}
    local ns_flag=""
    if [ -n "${ns}" ]; then
        ns_flag="-n ${ns}"
    fi
    # shellcheck disable=SC2086
    kubectl get "${resource}" ${ns_flag} "${name}" >/dev/null 2>&1
}

wait_for_condition() {
    local resource=$1 name=$2 condition=$3 ns=${4:-}
    local ns_flag=""
    if [ -n "${ns}" ]; then
        ns_flag="-n ${ns}"
    fi
    echo "  Waiting for ${resource}/${name} to be ${condition} ..."
    local retries=60
    while [ $retries -gt 0 ]; do
        # shellcheck disable=SC2086
        local val
        val=$(kubectl get "${resource}" ${ns_flag} "${name}" -o jsonpath="{.status.conditions[?(@.type==\"${condition}\")].status}" 2>/dev/null || true)
        if [ "${val}" = "True" ]; then
            return 0
        fi
        retries=$((retries - 1))
        sleep 5
    done
    echo "  ERROR: timed out waiting for ${resource}/${name} ${condition}"
    return 1
}

# ---------------------------------------------------------------------------
# 1. Calico Network CRD (projectcalico.org/v3 Network with l2Bridge)
# ---------------------------------------------------------------------------
echo "--- Calico Network CRD ---"
if skip_if_exists crd networks.projectcalico.org; then
    echo "  Already installed, skipping."
else
    kubectl apply -f - <<'EOF'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: networks.projectcalico.org
spec:
  group: projectcalico.org
  names:
    kind: Network
    listKind: NetworkList
    plural: networks
    singular: network
  preserveUnknownFields: false
  scope: Cluster
  versions:
  - name: v3
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            type: string
          kind:
            type: string
          metadata:
            type: object
          spec:
            properties:
              l2Bridge:
                properties:
                  vlans:
                    items:
                      properties:
                        vlan:
                          properties:
                            id:
                              type: integer
                              minimum: 1
                              maximum: 4094
                          type: object
                        subnets:
                          items:
                            properties:
                              cidr:
                                type: string
                            type: object
                          type: array
                      type: object
                    type: array
                type: object
              vrf:
                type: object
                x-kubernetes-preserve-unknown-fields: true
            type: object
          status:
            type: object
            x-kubernetes-preserve-unknown-fields: true
        type: object
    served: true
    storage: true
    subresources:
      status: {}
EOF
    echo "  Installed."
fi
echo

# ---------------------------------------------------------------------------
# 2. Calico Network CR and IPPool
# ---------------------------------------------------------------------------
echo "--- Calico Network and IPPool ---"
if skip_if_exists network.projectcalico.org default; then
    echo "  Network 'default' already exists, skipping."
else
    kubectl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: Network
metadata:
  name: default
spec:
  l2Bridge:
    vlans:
    - vlan:
        id: ${VLAN_ID}
      subnets:
      - cidr: "${VLAN_SUBNET}"
EOF
    echo "  Network 'default' created (VLAN ${VLAN_ID}, subnet ${VLAN_SUBNET})."
fi

if skip_if_exists ippool.projectcalico.org migration-pool; then
    echo "  IPPool 'migration-pool' already exists, skipping."
else
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
    echo "  IPPool 'migration-pool' created (${VLAN_SUBNET})."
fi
echo

# ---------------------------------------------------------------------------
# 3. Target namespace and Calico NetworkAttachmentDefinition
# ---------------------------------------------------------------------------
echo "--- Target namespace and NAD ---"
kubectl create namespace "${TARGET_NS}" --dry-run=client -o yaml | kubectl apply -f -

if skip_if_exists net-attach-def calico-net "${TARGET_NS}"; then
    echo "  NAD 'calico-net' already exists, skipping."
else
    kubectl apply -f - <<EOF
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: calico-net
  namespace: ${TARGET_NS}
spec:
  config: |
    {
      "cniVersion": "0.3.1",
      "type": "calico",
      "policy": { "type": "k8s" },
      "datastore_type": "kubernetes",
      "kubernetes": { "k8s_api_root": "https://10.96.0.1:443", "kubeconfig": "/etc/cni/net.d/calico-kubeconfig" },
      "network": "default",
      "ipam": {
        "type": "calico-ipam"
      }
    }
EOF
    echo "  NAD 'calico-net' created in ${TARGET_NS}."
fi
echo

# ---------------------------------------------------------------------------
# 4. vSphere Provider (pointing at vcsim)
# ---------------------------------------------------------------------------
echo "--- vSphere Provider ---"
if skip_if_exists provider vsphere-vcsim "${FORKLIFT_NS}"; then
    echo "  Already exists, skipping."
else
    # Secret
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: vsphere-vcsim
  namespace: ${FORKLIFT_NS}
  labels:
    createdForResourceType: providers
    createdForResource: vsphere-vcsim
    createdForProviderType: vsphere
type: Opaque
stringData:
  user: "${VCSIM_USER}"
  password: "${VCSIM_PASSWORD}"
  thumbprint: ""
  insecureSkipVerify: "true"
EOF

    # Provider
    kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: Provider
metadata:
  name: vsphere-vcsim
  namespace: ${FORKLIFT_NS}
spec:
  type: vsphere
  url: ${VCSIM_URL}
  secret:
    name: vsphere-vcsim
    namespace: ${FORKLIFT_NS}
  settings:
    vddkInitImage: ""
    sdkEndpoint: vcenter
EOF
    echo "  Created. Waiting for provider to be Ready ..."
    wait_for_condition provider vsphere-vcsim Ready "${FORKLIFT_NS}"
    echo "  Provider is Ready."
fi
echo

# ---------------------------------------------------------------------------
# 5. NetworkMap and StorageMap
# ---------------------------------------------------------------------------
echo "--- NetworkMap ---"
if skip_if_exists networkmap vcsim-calico-netmap "${FORKLIFT_NS}"; then
    echo "  Already exists, skipping."
else
    kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: NetworkMap
metadata:
  name: vcsim-calico-netmap
  namespace: ${FORKLIFT_NS}
spec:
  provider:
    source:
      name: vsphere-vcsim
      namespace: ${FORKLIFT_NS}
    destination:
      name: host
      namespace: ${FORKLIFT_NS}
  map:
  - source:
      id: ${NETWORK_ID}
    destination:
      type: multus
      name: calico-net
      namespace: ${TARGET_NS}
EOF
    wait_for_condition networkmap vcsim-calico-netmap Ready "${FORKLIFT_NS}"
    echo "  NetworkMap is Ready."
fi

echo "--- StorageMap ---"
if skip_if_exists storagemap vcsim-storagemap "${FORKLIFT_NS}"; then
    echo "  Already exists, skipping."
else
    kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: StorageMap
metadata:
  name: vcsim-storagemap
  namespace: ${FORKLIFT_NS}
spec:
  provider:
    source:
      name: vsphere-vcsim
      namespace: ${FORKLIFT_NS}
    destination:
      name: host
      namespace: ${FORKLIFT_NS}
  map:
  - source:
      id: ${DATASTORE_ID}
    destination:
      storageClass: ${STORAGE_CLASS}
      accessMode: ReadWriteOnce
EOF
    wait_for_condition storagemap vcsim-storagemap Ready "${FORKLIFT_NS}"
    echo "  StorageMap is Ready."
fi
echo

# ---------------------------------------------------------------------------
# 6. Migration Plan
# ---------------------------------------------------------------------------
echo "--- Migration Plan ---"
if skip_if_exists plan vcsim-calico-plan "${FORKLIFT_NS}"; then
    echo "  Already exists, skipping."
else
    kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: Plan
metadata:
  name: vcsim-calico-plan
  namespace: ${FORKLIFT_NS}
spec:
  provider:
    source:
      name: vsphere-vcsim
      namespace: ${FORKLIFT_NS}
    destination:
      name: host
      namespace: ${FORKLIFT_NS}
  map:
    network:
      name: vcsim-calico-netmap
      namespace: ${FORKLIFT_NS}
    storage:
      name: vcsim-storagemap
      namespace: ${FORKLIFT_NS}
  targetNamespace: ${TARGET_NS}
  type: cold
  vms:
  - id: ${VM_ID}
    name: ${VM_NAME}
EOF
    echo "  Plan created."
fi

# Show plan conditions (some warnings are expected with vcsim VMs)
echo "  Plan conditions:"
kubectl get plan vcsim-calico-plan -n "${FORKLIFT_NS}" \
    -o jsonpath='{range .status.conditions[*]}    {.type}: {.status} ({.category}) - {.message}{"\n"}{end}' 2>/dev/null || true
echo

# NOTE: The Plan may not reach Ready state with vcsim because simulated VMs
# report GuestToolsIssue (Critical). The vcsim VMs have no VMware Tools
# installed and are powered on, which triggers the GuestToolsInstalled
# validator. To work around this:
#   - Power off the VM in vcsim before creating the Plan, OR
#   - Use a real vCenter with VMware Tools installed on the source VM.
#
# If the Plan has a Ready condition, proceed to create the Migration.

echo "--- Check Plan readiness ---"
PLAN_READY=$(kubectl get plan vcsim-calico-plan -n "${FORKLIFT_NS}" \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)

if [ "${PLAN_READY}" = "True" ]; then
    echo "  Plan is Ready."
else
    echo "  Plan is NOT Ready (expected with vcsim — GuestToolsIssue blocks readiness)."
    echo "  The GuestToolsIssue condition fires because vcsim VMs have no VMware Tools."
    echo "  Skipping Migration creation."
    echo
    echo "=== Simulation setup complete (Plan not Ready — see notes above) ==="
    exit 0
fi

# ---------------------------------------------------------------------------
# 7. Migration
# ---------------------------------------------------------------------------
echo "--- Migration ---"
if skip_if_exists migration vcsim-calico-migration "${FORKLIFT_NS}"; then
    echo "  Already exists, skipping."
else
    kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: Migration
metadata:
  name: vcsim-calico-migration
  namespace: ${FORKLIFT_NS}
spec:
  plan:
    name: vcsim-calico-plan
    namespace: ${FORKLIFT_NS}
EOF
    echo "  Migration created."
fi

echo "  Migration conditions:"
kubectl get migration vcsim-calico-migration -n "${FORKLIFT_NS}" \
    -o jsonpath='{range .status.conditions[*]}    {.type}: {.status} - {.message}{"\n"}{end}' 2>/dev/null || true
echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Simulation setup complete ==="
echo
echo "Resources created in ${FORKLIFT_NS}:"
echo "  Provider:    vsphere-vcsim  → ${VCSIM_URL}"
echo "  NetworkMap:  vcsim-calico-netmap  (${NETWORK_ID} → ${TARGET_NS}/calico-net)"
echo "  StorageMap:  vcsim-storagemap  (${DATASTORE_ID} → ${STORAGE_CLASS})"
echo "  Plan:        vcsim-calico-plan  (${VM_NAME})"
echo "  Migration:   vcsim-calico-migration"
echo
echo "Resources created cluster-wide:"
echo "  CRD:         networks.projectcalico.org"
echo "  Network:     default (l2Bridge, VLAN ${VLAN_ID}, subnet ${VLAN_SUBNET})"
echo "  IPPool:      migration-pool (${VLAN_SUBNET})"
echo
echo "Resources created in ${TARGET_NS}:"
echo "  NAD:         calico-net (type: calico, network: default)"
echo
echo "To check migration progress:"
echo "  kubectl get migration -n ${FORKLIFT_NS}"
echo "  kubectl get plan -n ${FORKLIFT_NS} -o yaml"
echo "  kubectl get pods -n ${TARGET_NS}"
echo
echo "To clean up:"
echo "  kubectl delete migration,plan,networkmap,storagemap -n ${FORKLIFT_NS} --all"
echo "  kubectl delete provider vsphere-vcsim -n ${FORKLIFT_NS}"
echo "  kubectl delete secret vsphere-vcsim -n ${FORKLIFT_NS}"
echo "  kubectl delete ns ${TARGET_NS}"
echo "  kubectl delete network.projectcalico.org default"
echo "  kubectl delete ippool.projectcalico.org migration-pool"
echo "  kubectl delete crd networks.projectcalico.org"
