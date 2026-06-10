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

# 01-deploy-forklift-prereqs.sh — installs prerequisites for testing Forklift
# vSphere-to-KubeVirt migrations on a KIND cluster that already has Calico
# and MockVirt deployed.
#
# This script installs:
#   1. Multus CNI (thin plugin)
#   2. vcsim (VMware vCenter simulator)
#   3. cert-manager
#   4. CDI (Containerized Data Importer)
#   5. CNA (Cluster Network Addons)
#   6. OLM (Operator Lifecycle Manager)
#
# Every step is idempotent — already-installed components are skipped.
#
# Usage:
#   ./hack/test/kind/forklift/01-deploy-forklift-prereqs.sh
#
# Prerequisites:
#   - A KIND cluster with Calico and MockVirt already deployed
#   - kubectl configured to talk to the cluster
#
# Environment variables (all optional):
#   KUBECONFIG   Path to kubeconfig (default: hack/test/kind/kind-kubeconfig.yaml)

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../../.."; pwd)

export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/hack/test/kind/kind-kubeconfig.yaml}"

echo "=== Deploy Forklift prerequisites ==="
echo "  Kubeconfig: ${KUBECONFIG}"
echo

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
wait_for_deployment() {
    local ns=$1 name=$2
    echo "  Waiting for ${ns}/${name} ..."
    kubectl wait --for=condition=Available --timeout=300s deployment -n "${ns}" "${name}"
}

wait_for_all_deployments() {
    local ns=$1
    echo "  Waiting for all deployments in ${ns} ..."
    kubectl wait --for=condition=Available --timeout=300s deployment -n "${ns}" --all
}

skip_if_exists() {
    local resource=$1 name=$2 ns=${3:-}
    local ns_flag=""
    if [ -n "${ns}" ]; then
        ns_flag="-n ${ns}"
    fi
    # shellcheck disable=SC2086
    kubectl get "${resource}" ${ns_flag} "${name}" >/dev/null 2>&1
}

# --------------------------------------------------------------------------
# 1. Multus CNI (thin plugin)
# --------------------------------------------------------------------------
echo "--- Multus CNI ---"
if skip_if_exists daemonset kube-multus-ds kube-system; then
    echo "  Already installed, skipping."
else
    kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset.yml
    kubectl -n kube-system rollout status daemonset/kube-multus-ds --timeout=120s
    echo "  Installed."
fi
echo

# --------------------------------------------------------------------------
# 2. vcsim (VMware vCenter simulator)
# --------------------------------------------------------------------------
echo "--- vcsim ---"
if skip_if_exists deployment vcsim default; then
    echo "  Already installed, skipping."
else
    kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vcsim
  namespace: default
spec:
  selector:
    matchLabels:
      app: vcsim
  template:
    metadata:
      labels:
        app: vcsim
    spec:
      containers:
        - name: vcsim
          image: vmware/vcsim:latest
          ports:
            - name: https
              containerPort: 8989
---
apiVersion: v1
kind: Service
metadata:
  name: vcsim
  namespace: default
spec:
  selector:
    app: vcsim
  ports:
    - port: 8989
      targetPort: 8989
EOF
    kubectl rollout status deployment/vcsim -n default --timeout=120s
    echo "  Installed (service: vcsim.default.svc:8989)."
fi
echo

# --------------------------------------------------------------------------
# 3. cert-manager
# --------------------------------------------------------------------------
echo "--- cert-manager ---"
if kubectl get namespace cert-manager >/dev/null 2>&1; then
    echo "  Already installed, skipping."
else
    CERT_MANAGER_VERSION=$(curl -s https://api.github.com/repos/cert-manager/cert-manager/releases/latest | grep 'tag_name' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "  Version: ${CERT_MANAGER_VERSION}"
    kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
    wait_for_all_deployments cert-manager
    echo "  Installed."
fi
echo

# --------------------------------------------------------------------------
# 4. CDI (Containerized Data Importer)
# --------------------------------------------------------------------------
echo "--- CDI ---"
if kubectl get namespace cdi >/dev/null 2>&1; then
    echo "  Already installed, skipping."
else
    CDI_VERSION=$(curl -s https://api.github.com/repos/kubevirt/containerized-data-importer/releases/latest | grep 'tag_name' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "  Version: ${CDI_VERSION}"
    kubectl create -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-operator.yaml" --dry-run=client -o yaml | kubectl apply -f -
    kubectl create -f "https://github.com/kubevirt/containerized-data-importer/releases/download/${CDI_VERSION}/cdi-cr.yaml" --dry-run=client -o yaml | kubectl apply -f -
    wait_for_deployment cdi cdi-operator
    echo "  Installed."
fi
echo

# --------------------------------------------------------------------------
# 5. CNA (Cluster Network Addons)
# --------------------------------------------------------------------------
echo "--- Cluster Network Addons ---"
if kubectl get namespace cluster-network-addons >/dev/null 2>&1; then
    echo "  Already installed, skipping."
else
    CNA_VERSION=$(curl -s https://api.github.com/repos/kubevirt/cluster-network-addons-operator/releases/latest | grep 'tag_name' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "  Version: ${CNA_VERSION}"
    kubectl apply -f "https://github.com/kubevirt/cluster-network-addons-operator/releases/download/${CNA_VERSION}/namespace.yaml"
    kubectl apply -f "https://github.com/kubevirt/cluster-network-addons-operator/releases/download/${CNA_VERSION}/network-addons-config.crd.yaml"
    kubectl apply -f "https://github.com/kubevirt/cluster-network-addons-operator/releases/download/${CNA_VERSION}/operator.yaml"
    wait_for_deployment cluster-network-addons cluster-network-addons-operator
    cat <<'NACEOF' | kubectl apply -f -
apiVersion: networkaddonsoperator.network.kubevirt.io/v1
kind: NetworkAddonsConfig
metadata:
  name: cluster
  namespace: cluster-network-addons
spec:
  multus: {}
  linuxBridge: {}
  macvtap: {}
  imagePullPolicy: Always
NACEOF
    kubectl wait --for=condition=Available --timeout=300s networkaddonsconfig cluster
    echo "  Installed."
fi
echo

# --------------------------------------------------------------------------
# 6. OLM (Operator Lifecycle Manager)
# --------------------------------------------------------------------------
echo "--- OLM ---"
if kubectl get namespace olm >/dev/null 2>&1; then
    echo "  Already installed, skipping."
else
    kubectl apply -f https://raw.githubusercontent.com/operator-framework/operator-lifecycle-manager/master/deploy/upstream/quickstart/crds.yaml
    kubectl apply -f https://raw.githubusercontent.com/operator-framework/operator-lifecycle-manager/master/deploy/upstream/quickstart/olm.yaml
    wait_for_deployment olm olm-operator
    wait_for_deployment olm catalog-operator
    echo "  Installed."
fi
echo

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo "=== All Forklift prerequisites installed ==="
echo
echo "  Multus:        $(kubectl get daemonset -n kube-system kube-multus-ds -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 'N/A') nodes ready"
echo "  vcsim:         vcsim.default.svc:8989"
echo "  cert-manager:  $(kubectl get deployment -n cert-manager cert-manager -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 'N/A') replica(s)"
echo "  CDI:           $(kubectl get deployment -n cdi cdi-operator -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 'N/A') replica(s)"
echo "  CNA:           $(kubectl get deployment -n cluster-network-addons cluster-network-addons-operator -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 'N/A') replica(s)"
echo "  OLM:           $(kubectl get deployment -n olm olm-operator -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 'N/A') replica(s)"
echo
echo "Ready to build and deploy Forklift."
