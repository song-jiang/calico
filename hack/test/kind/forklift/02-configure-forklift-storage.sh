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

# 02-configure-forklift-storage.sh — makes a StorageClass usable as backing
# storage for Forklift/CDI VM disk imports on a KIND cluster.
#
# Why this is needed:
#   KIND ships the rancher.io/local-path provisioner, which CDI does not
#   recognise. CDI therefore leaves the StorageClass's StorageProfile with an
#   empty claimPropertySets (condition Recognized=False, UnrecognizedProvisioner)
#   and cannot infer an accessMode/volumeMode. Forklift's builder relies on the
#   StorageProfile to stamp those onto the importer DataVolumes/PVCs, so VM disk
#   provisioning stalls even though the StorageClass itself works.
#
#   This script populates the StorageProfile's claimPropertySets explicitly.
#   local-path supports only ReadWriteOnce + Filesystem, which is sufficient for
#   the cold-migration path (no RWX live migration, no Block volumeMode).
#
# Idempotent: re-running just re-applies the same merge patch.
#
# Usage:
#   ./hack/test/kind/forklift/02-configure-forklift-storage.sh
#
# Environment variables (all optional):
#   KUBECONFIG     Path to kubeconfig (default: hack/test/kind/kind-kubeconfig.yaml)
#   STORAGE_CLASS  StorageClass / StorageProfile to configure (default: the
#                  cluster's default StorageClass)
#   ACCESS_MODES   Comma-separated access modes (default: ReadWriteOnce)
#   VOLUME_MODE    Volume mode (default: Filesystem)

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/../../../.."; pwd)

export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/hack/test/kind/kind-kubeconfig.yaml}"

: "${ACCESS_MODES:=ReadWriteOnce}"
: "${VOLUME_MODE:=Filesystem}"

echo "=== Configure Forklift/CDI VM storage ==="
echo "  Kubeconfig: ${KUBECONFIG}"
echo

# ---------------------------------------------------------------------------
# Preflight: CDI StorageProfile CRD must be present.
# ---------------------------------------------------------------------------
if ! kubectl get crd storageprofiles.cdi.kubevirt.io >/dev/null 2>&1; then
    echo "ERROR: CDI StorageProfile CRD not found — is CDI installed?" >&2
    echo "       Run ./hack/test/kind/forklift/01-deploy-forklift-prereqs.sh first." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Resolve the target StorageClass (default: the cluster default).
# ---------------------------------------------------------------------------
if [ -z "${STORAGE_CLASS:-}" ]; then
    STORAGE_CLASS=$(kubectl get storageclass \
        -o jsonpath='{range .items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")]}{.metadata.name}{"\n"}{end}' \
        2>/dev/null | head -n1)
fi
if [ -z "${STORAGE_CLASS}" ]; then
    echo "ERROR: no StorageClass specified and no default StorageClass found." >&2
    echo "       Set STORAGE_CLASS=<name> and re-run." >&2
    exit 1
fi

echo "  StorageClass: ${STORAGE_CLASS}"
echo "  Access modes: ${ACCESS_MODES}"
echo "  Volume mode:  ${VOLUME_MODE}"
echo

# ---------------------------------------------------------------------------
# Wait for CDI to create the StorageProfile for this StorageClass.
# CDI generates one profile per StorageClass; it may lag just after install.
# ---------------------------------------------------------------------------
echo "--- Waiting for StorageProfile/${STORAGE_CLASS} ---"
for _ in $(seq 1 30); do
    if kubectl get storageprofile "${STORAGE_CLASS}" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
if ! kubectl get storageprofile "${STORAGE_CLASS}" >/dev/null 2>&1; then
    echo "ERROR: StorageProfile/${STORAGE_CLASS} never appeared." >&2
    echo "       Check that StorageClass '${STORAGE_CLASS}' exists and CDI is healthy." >&2
    exit 1
fi

current=$(kubectl get storageprofile "${STORAGE_CLASS}" -o jsonpath='{.status.claimPropertySets}' 2>/dev/null)
echo "  Current claimPropertySets: ${current:-<empty>}"
echo

# ---------------------------------------------------------------------------
# Build the claimPropertySets patch and apply it.
# ACCESS_MODES is comma-separated -> JSON array of quoted strings.
# ---------------------------------------------------------------------------
access_json=$(echo "${ACCESS_MODES}" | awk -F, '{
    out="";
    for (i = 1; i <= NF; i++) {
        if (i > 1) out = out ",";
        out = out "\"" $i "\"";
    }
    print out;
}')

patch="{\"spec\":{\"claimPropertySets\":[{\"accessModes\":[${access_json}],\"volumeMode\":\"${VOLUME_MODE}\"}]}}"

echo "--- Patching StorageProfile/${STORAGE_CLASS} ---"
kubectl patch storageprofile "${STORAGE_CLASS}" --type merge -p "${patch}"
echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Done ==="
echo "  StorageProfile/${STORAGE_CLASS} claimPropertySets:"
kubectl get storageprofile "${STORAGE_CLASS}" \
    -o jsonpath='{range .status.claimPropertySets[*]}    accessModes={.accessModes} volumeMode={.volumeMode}{"\n"}{end}'
echo
echo "Forklift/CDI can now provision VM disks on StorageClass '${STORAGE_CLASS}'."
echo "Note: ${ACCESS_MODES} + ${VOLUME_MODE} supports cold migration only"
echo "      (no RWX live migration, no Block volumeMode on local-path)."
