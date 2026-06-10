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

# 00-deploy-mockvirt.sh — downloads and deploys MockVirt (KubeVirt simulation
# mode) onto an existing KIND cluster.
#
# Usage:
#   ./hack/test/kind/forklift/00-deploy-mockvirt.sh
#
# Environment variables (all optional):
#   MOCKVIRT_RELEASE_URL  Base URL for release assets
#                         (default: https://github.com/tigera/kubevirt/releases/download/mockvirt-v1.8.1)
#   MOCKVIRT_KUBECONFIG   Path to kubeconfig
#                         (default: hack/test/kind/kind-kubeconfig.yaml)
#   MOCKVIRT_MANIFESTS_DIR  Directory for downloaded manifests
#                           (default: /tmp/kubevirt-manifests)

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../../.."; pwd)

: "${MOCKVIRT_RELEASE_URL:=https://github.com/tigera/kubevirt/releases/download/mockvirt-v1.8.1}"
: "${MOCKVIRT_KUBECONFIG:=${REPO_ROOT}/hack/test/kind/kind-kubeconfig.yaml}"
: "${MOCKVIRT_MANIFESTS_DIR:=/tmp/kubevirt-manifests}"

echo "=== Deploy MockVirt ==="
echo "  Release URL:    ${MOCKVIRT_RELEASE_URL}"
echo "  Kubeconfig:     ${MOCKVIRT_KUBECONFIG}"
echo "  Manifests dir:  ${MOCKVIRT_MANIFESTS_DIR}"
echo

# Download release assets
mkdir -p "${MOCKVIRT_MANIFESTS_DIR}"
for asset in ci-deploy-kind.sh kubevirt-operator.yaml kubevirt-cr.yaml; do
    echo "Downloading ${asset} ..."
    curl --retry 9 --retry-all-errors -fsSL \
        "${MOCKVIRT_RELEASE_URL}/${asset}" \
        -o "${MOCKVIRT_MANIFESTS_DIR}/${asset}"
done
chmod +x "${MOCKVIRT_MANIFESTS_DIR}/ci-deploy-kind.sh"

# Deploy
echo
echo "Running ci-deploy-kind.sh ..."
MOCKVIRT_KUBECONFIG="${MOCKVIRT_KUBECONFIG}" \
MOCKVIRT_MANIFESTS_DIR="${MOCKVIRT_MANIFESTS_DIR}" \
    "${MOCKVIRT_MANIFESTS_DIR}/ci-deploy-kind.sh"

echo
echo "MockVirt deployed successfully."
