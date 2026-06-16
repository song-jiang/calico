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

# 03-deploy-forklift.sh — deploys the Forklift operator + controller onto the
# KIND cluster via OLM, then creates the ForkliftController CR. This is the
# step that was previously an undocumented dependency between 02 and 04: the
# earlier scripts install prerequisites (01) and storage (02), but nothing
# stood up Forklift itself before 04-create-migration-crs.sh started creating
# CRs against it.
#
# This is a SIMPLIFIED, no-argument port of the Forklift repo's
# hack/deploy-forklift-kind.sh. It only performs the *deploy* half (OLM
# CatalogSource/OperatorGroup/Subscription + ForkliftController CR) using
# images already present in the local kind-registry.
#
# ===========================================================================
# REMAINING DEPENDENCY ON THE FORKLIFT REPO (cannot be done from this repo)
# ===========================================================================
# The Forklift container images do not exist publicly under localhost:5000 —
# they must be BUILT FROM THE FORKLIFT REPO SOURCE and pushed to the local
# kind-registry first. There is no Forklift source in the calico repo, so this
# script cannot build them; it only consumes them.
#
# Before running this script, from a checkout of github.com/kubev2v/forklift:
#
#     REGISTRY=localhost:5000 REGISTRY_ORG=projectalexo REGISTRY_TAG=dev \
#       BUILD_IMAGES=true ./hack/deploy-forklift-kind.sh
#
# (or the equivalent make build-*-image / push-*-image + bundle + index
# targets). That produces, in the local registry:
#     localhost:5000/projectalexo/forklift-controller:dev-amd64
#     localhost:5000/projectalexo/forklift-api:dev-amd64
#     localhost:5000/projectalexo/forklift-validation:dev-amd64
#     localhost:5000/projectalexo/forklift-operator:dev-amd64
#     localhost:5000/projectalexo/forklift-virt-v2v:dev-amd64
#     localhost:5000/projectalexo/populator-controller:dev-amd64
#     localhost:5000/projectalexo/forklift-operator-bundle:dev-amd64
#     localhost:5000/projectalexo/forklift-operator-index:dev-amd64
#
# This script preflight-checks for the index image and aborts with the above
# instructions if it is missing.
#
# Other prerequisites (satisfied by the earlier scripts in this directory):
#   - 01-deploy-forklift-prereqs.sh: OLM, cert-manager, CDI, CNA, Multus, vcsim
#   - 02-configure-forklift-storage.sh: CDI StorageProfile populated
#   - The local kind-registry running and mirrored into the kind nodes
#     (created by calico's `make kind-up`).
#
# Usage:
#   ./hack/test/kind/forklift/03-deploy-forklift.sh
#
# Environment variables (all optional — defaults match the other scripts):
#   KUBECONFIG     kubeconfig (default: hack/test/kind/kind-kubeconfig.yaml)
#   NAMESPACE      Forklift namespace (default: konveyor-forklift)
#   REGISTRY       image registry (default: localhost:5000)
#   REGISTRY_ORG   image org/user (default: projectalexo)
#   REGISTRY_TAG   image tag (default: dev)
#   PLATFORM_ARCH  image arch suffix (default: amd64)

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../../.."; pwd)

export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/hack/test/kind/kind-kubeconfig.yaml}"

NAMESPACE="${NAMESPACE:-konveyor-forklift}"
REGISTRY="${REGISTRY:-localhost:5000}"
REGISTRY_ORG="${REGISTRY_ORG:-projectalexo}"
REGISTRY_TAG="${REGISTRY_TAG:-dev}"
PLATFORM_ARCH="${PLATFORM_ARCH:-amd64}"

INDEX_IMAGE="${REGISTRY}/${REGISTRY_ORG}/forklift-operator-index:${REGISTRY_TAG}-${PLATFORM_ARCH}"

echo "=== Deploy Forklift (operator + controller) via OLM ==="
echo "  Kubeconfig:  ${KUBECONFIG}"
echo "  Namespace:   ${NAMESPACE}"
echo "  Index image: ${INDEX_IMAGE}"
echo

# ---------------------------------------------------------------------------
# Preflight: the index image must already be in the local registry.
# (See the REMAINING DEPENDENCY note in the header.)
# ---------------------------------------------------------------------------
echo "--- Preflight: forklift images in local registry ---"
reg_host="${REGISTRY}"
reg_repo="${REGISTRY_ORG}/forklift-operator-index"
if curl -fs "http://${reg_host}/v2/${reg_repo}/tags/list" 2>/dev/null | grep -q "\"${REGISTRY_TAG}-${PLATFORM_ARCH}\""; then
    echo "  Found ${INDEX_IMAGE}."
else
    echo "  ERROR: ${INDEX_IMAGE} is not in the local registry." >&2
    echo "  The Forklift images must be built and pushed FROM THE FORKLIFT REPO first:" >&2
    echo >&2
    echo "    REGISTRY=${REGISTRY} REGISTRY_ORG=${REGISTRY_ORG} REGISTRY_TAG=${REGISTRY_TAG} \\" >&2
    echo "      BUILD_IMAGES=true ./hack/deploy-forklift-kind.sh   # in github.com/kubev2v/forklift" >&2
    echo >&2
    echo "  (This calico repo has no Forklift source, so the images cannot be built here.)" >&2
    exit 1
fi
echo

# ---------------------------------------------------------------------------
# 1. OLM resources: CatalogSource (-> local index image), OperatorGroup,
#    Subscription. Mirrors the Forklift repo's operator/forklift-k8s-dev.yaml.
# ---------------------------------------------------------------------------
echo "--- Deploying OLM resources ---"
kubectl apply -f - <<EOF
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
---
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: konveyor-forklift
  namespace: ${NAMESPACE}
spec:
  displayName: Forklift Operator
  publisher: Konveyor
  sourceType: grpc
  image: ${INDEX_IMAGE}
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: migration
  namespace: ${NAMESPACE}
spec:
  targetNamespaces:
    - ${NAMESPACE}
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: forklift-operator
  namespace: ${NAMESPACE}
spec:
  channel: development
  installPlanApproval: Automatic
  name: forklift-operator
  source: konveyor-forklift
  sourceNamespace: ${NAMESPACE}
EOF
echo

# ---------------------------------------------------------------------------
# 2. Wait for the CatalogSource to connect and the CSV to install.
# ---------------------------------------------------------------------------
echo "--- Waiting for CatalogSource READY ---"
kubectl wait --for=jsonpath='{.status.connectionState.lastObservedState}'=READY \
    catalogsource/konveyor-forklift -n "${NAMESPACE}" --timeout=180s

echo "--- Waiting for CSV ---"
for _ in $(seq 1 60); do
    csv=$(kubectl get csv -n "${NAMESPACE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    [ -n "${csv}" ] && { echo "  CSV: ${csv}"; break; }
    sleep 5
done
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded csv -n "${NAMESPACE}" --all --timeout=300s
echo

# ---------------------------------------------------------------------------
# 3. ForkliftController CR — the operator reconciles it into the control plane
#    (controller, api, inventory, validation, populator). Matches the Forklift
#    repo's hack/deploy-k8s-controller.sh.
# ---------------------------------------------------------------------------
echo "--- Creating ForkliftController CR ---"
kubectl apply -f - <<EOF
apiVersion: forklift.konveyor.io/v1beta1
kind: ForkliftController
metadata:
  name: forklift-controller
  namespace: ${NAMESPACE}
spec:
  k8s_cluster: "true"
  feature_ui_plugin: "false"
  feature_cli_download: "false"
  feature_ocp_live_migration: "false"
EOF
echo

# ---------------------------------------------------------------------------
# 4. Verify the core control-plane deployments come up.
# ---------------------------------------------------------------------------
echo "--- Waiting for forklift-controller ---"
for _ in $(seq 1 60); do
    ready=$(kubectl get deployment forklift-controller -n "${NAMESPACE}" \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)
    [ "${ready:-0}" -ge 1 ] 2>/dev/null && break
    sleep 5
done

echo
echo "=== Forklift deployed. Pods: ==="
kubectl get pods -n "${NAMESPACE}"
echo
ready=$(kubectl get deployment forklift-controller -n "${NAMESPACE}" \
    -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)
if [ "${ready:-0}" -ge 1 ] 2>/dev/null; then
    echo "forklift-controller is Ready. Continue with 04-create-migration-crs.sh."
else
    echo "WARNING: forklift-controller not Ready yet — check 'kubectl get pods -n ${NAMESPACE}'."
    echo "If component pods are ImagePullBackOff, the per-component images are missing"
    echo "from the local registry (see the REMAINING DEPENDENCY note in this script's header)."
fi
