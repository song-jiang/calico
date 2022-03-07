#!/bin/bash
# Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

: ${KUBECTL:=./bin/kubectl}
KCAPZ="${KUBECTL} --kubeconfig=./kubeconfig"

: ${PRODUCT:=calico}
: ${RELEASE_STREAM:=""} # Default to latest version, set to e.g. v3.11 
: ${HASH_RELEASE:="false"} # Set to true to use hash release

echo Settings:
echo '  PRODUCT='${PRODUCT}
echo '  RELEASE_STREAM='${RELEASE_STREAM}
echo '  HASH_RELEASE='${HASH_RELEASE}

if [ ${PRODUCT} == 'calient' ]; then
    RELEASE_BASE_URL="https://docs.tigera.io/${RELEASE_STREAM}"
else
    RELEASE_BASE_URL="https://projectcalico.docs.tigera.io/${RELEASE_STREAM}"
fi

if [ ${HASH_RELEASE} == 'true' ]; then
    if [ -z ${RELEASE_STREAM} ]; then
	    echo "RELEASE_STREAM not set for HASH release"
	    exit -1
    fi
    if [ ${PRODUCT} == 'calient' ]; then
      URL_HASH="https://latest-cnx.docs.eng.tigera.net/${RELEASE_STREAM}.txt"
    else
      URL_HASH="https://latest-os.docs.eng.tigera.net/${RELEASE_STREAM}.txt"
    fi
    RELEASE_BASE_URL=$(curl -sS ${URL_HASH})
fi

# Check release url and installation scripts
echo "Set release base url ${RELEASE_BASE_URL}"

# Install on Linux side
${KCAPZ} create -f ${RELEASE_BASE_URL}/manifests/tigera-operator.yaml

${KCAPZ} create -f ${RELEASE_BASE_URL}/manifests/custom-resources.yaml

watch ${KCAPZ} get pods -n calico-system

# Install on Windows side
