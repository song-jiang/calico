#!/bin/bash
# Copyright (c) 2022 Tigera, Inc. All rights reserved.
# Copyright 2020 The Kubernetes Authors.
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

set -o errexit
set -o nounset
set -o pipefail

# Verify the required Environment Variables are present.
: "${CLUSTER_NAME_CAPZ:?Environment variable empty or not defined.}"
: "${AZURE_LOCATION:?Environment variable empty or not defined.}"
: "${KUBE_VERSION:?Environment variable empty or not defined.}"

: "${AZURE_SUBSCRIPTION_ID:?Environment variable empty or not defined.}"
: "${AZURE_TENANT_ID:?Environment variable empty or not defined.}"
: "${AZURE_CLIENT_ID:?Environment variable empty or not defined.}"
: "${AZURE_CLIENT_SECRET:?Environment variable empty or not defined.}"

# Number of Linux node is same as number of Windows nodes
: ${WIN_NODE_COUNT:=2}
TOTAL_NODES=$((WIN_NODE_COUNT*2+1))

echo Settings:
echo '  CLUSTER_NAME_CAPZ='${CLUSTER_NAME_CAPZ}
echo '  AZURE_LOCATION='${AZURE_LOCATION}
echo '  KUBE_VERSION='${KUBE_VERSION}
echo '  WIN_NODE_COUNT='${WIN_NODE_COUNT}

# [Optional] Select resource group. The default value is ${CLUSTER_NAME_CAPZ}.
AZURE_RESOURCE_GROUP="$CLUSTER_NAME_CAPZ"

# Utilities
: ${KIND:=./bin/kind}
: ${KUBECTL:=./bin/kubectl}
: ${CLUSTERCTL:=./bin/clusterctl}

# Base64 encode the variables
export AZURE_SUBSCRIPTION_ID_B64="$(echo -n "$AZURE_SUBSCRIPTION_ID" | base64 | tr -d '\n')"
export AZURE_TENANT_ID_B64="$(echo -n "$AZURE_TENANT_ID" | base64 | tr -d '\n')"
export AZURE_CLIENT_ID_B64="$(echo -n "$AZURE_CLIENT_ID" | base64 | tr -d '\n')"
export AZURE_CLIENT_SECRET_B64="$(echo -n "$AZURE_CLIENT_SECRET" | base64 | tr -d '\n')"

# Settings needed for AzureClusterIdentity used by the AzureCluster
export AZURE_CLUSTER_IDENTITY_SECRET_NAME="cluster-identity-secret"
export CLUSTER_IDENTITY_NAME="cluster-identity"
export AZURE_CLUSTER_IDENTITY_SECRET_NAMESPACE="default"

export EXP_MACHINE_POOL=true
export EXP_AKS=true

# Create management cluster
${KIND} delete cluster || true
${KIND} create cluster
${KUBECTL} wait node kind-control-plane --for=condition=ready --timeout=90s

sleep 30

# Initialise cluster

# Create a secret to include the password of the Service Principal identity created in Azure
# This secret will be referenced by the AzureClusterIdentity used by the AzureCluster
${KUBECTL} create secret generic "${AZURE_CLUSTER_IDENTITY_SECRET_NAME}" --from-literal=clientSecret="${AZURE_CLIENT_SECRET}"

# Finally, initialize the management cluster
${CLUSTERCTL} init --infrastructure azure

# Select VM types.
export AZURE_CONTROL_PLANE_MACHINE_TYPE="Standard_D2s_v3"
export AZURE_NODE_MACHINE_TYPE="Standard_D2s_v3"

# Generate SSH key.
rm .sshkey* || true
SSH_KEY_FILE=${SSH_KEY_FILE:-""}
if [ -z "$SSH_KEY_FILE" ]; then
    SSH_KEY_FILE=.sshkey
    rm -f "${SSH_KEY_FILE}" 2>/dev/null
    ssh-keygen -t rsa -b 2048 -f "${SSH_KEY_FILE}" -N '' -C "" 1>/dev/null
    echo "Machine SSH key generated in ${SSH_KEY_FILE}"
fi

AZURE_SSH_PUBLIC_KEY_B64=$(base64 "${SSH_KEY_FILE}.pub" | tr -d '\r\n')
export AZURE_SSH_PUBLIC_KEY_B64

# Windows sets the public key via cloudbase-init which take the raw text as input
AZURE_SSH_PUBLIC_KEY=$(< "${SSH_KEY_FILE}.pub" tr -d '\r\n')
export AZURE_SSH_PUBLIC_KEY

${CLUSTERCTL} generate cluster ${CLUSTER_NAME_CAPZ} \
  --kubernetes-version v${KUBE_VERSION} \
  --control-plane-machine-count=1 \
  --worker-machine-count=${WIN_NODE_COUNT}\
  --flavor machinepool-windows-containerd \
  > win-capz.yaml

function retry_command() {
  local RETRY=$(($1/10))
  local CMD=$2
  echo

  for i in `seq 1 $RETRY`; do
    echo Trying $CMD, attempt ${i}
    $CMD && return 0 || sleep 10
  done
}

retry_command 60 "${KUBECTL} apply -f win-capz.yaml"

# Wait for CAPZ deployments
${KUBECTL} wait --for=condition=Available --timeout=5m -n capz-system deployment -l cluster.x-k8s.io/provider=infrastructure-azure

# Wait for the kubeconfig to become available.
timeout --foreground 300 bash -c "while ! ${KUBECTL} get secrets | grep ${CLUSTER_NAME_CAPZ}-kubeconfig; do sleep 1; done"
# Get kubeconfig and store it locally.
${KUBECTL} get secrets ${CLUSTER_NAME_CAPZ}-kubeconfig -o json | jq -r .data.value | base64 --decode > ./kubeconfig
timeout --foreground 600 bash -c "while ! ${KUBECTL} --kubeconfig=./kubeconfig get nodes | grep control-plane; do sleep 1; done"
echo 'Cluster config is ready at ./kubeconfig. Run "${KUBECTL} --kubeconfig=./kubeconfig ..." to work with the new target cluster'

KCAPZ="${KUBECTL} --kubeconfig=./kubeconfig"
timeout --foreground 600 bash -c "while ! ${KCAPZ} get nodes | grep ${KUBE_VERSION} | wc -l | grep ${TOTAL_NODES}; do sleep 5; done"

echo seen all nodes

ID0=`kcapz get node -o wide | grep win-p-win000000 | awk '{print $6}' | awk -F '.' '{print $4}'`
ID1=`kcapz get node -o wide | grep win-p-win000001 | awk '{print $6}' | awk -F '.' '{print $4}'`
echo "ID0: $ID0, ID1:$ID1"
