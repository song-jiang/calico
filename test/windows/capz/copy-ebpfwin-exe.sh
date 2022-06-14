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

# Copy calico-felix.exe
cp ${CALICO_SRC_DIR}/felix/bin/ebpfwin.exe ./windows

./scp-node.sh $ID0 './windows/ebpfwin.exe' 'c:\k'

# Copy to staging
scp -i /home/song/cred/song-fv/master_ssh_key -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ./windows/ebpfwin.exe song@20.117.69.118:/home/song
