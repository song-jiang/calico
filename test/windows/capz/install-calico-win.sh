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
set -x

. export-env.sh

# strict affinity
curl -L https://github.com/projectcalico/calico/releases/download/v3.22.2/calicoctl-linux-amd64 -o calicoctl
chmod +x calicoctl
export CALICO_DATASTORE_TYPE=kubernetes
export CALICO_KUBECONFIG=./kubeconfig
./calicoctl get node --allow-version-mismatch
./calicoctl ipam configure --strictaffinity=true --allow-version-mismatch
echo "ipam configured with strict affinity"

# Install on Windows side

# Copy kubeconfig
./scp-node.sh $ID0 './kubeconfig' 'c:\k\config'

# Copy calico-felix.exe
cp ${CALICO_SRC_DIR}/felix/bin/calico-felix.exe ./windows

# Prepare ps1 files
curl -L https://docs.projectcalico.org/scripts/install-calico-windows.ps1 -o windows/install-calico-windows.ps1

./scp-node.sh $ID0 './windows/*' 'c:\k'

# Run setup scripts
# ./ssh-node.sh $ID0 'c:\k\setup-calico.ps1'
# ./ssh-node.sh $ID0 'c:\k\setup-kube-services.ps1'
# ./ssh-node.sh $ID0 'c:\k\setup-felix.ps1'
# ./ssh-node.sh $ID0 'c:\k\restart-felix.ps1'
