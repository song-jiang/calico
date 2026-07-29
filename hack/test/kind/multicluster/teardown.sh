#!/usr/bin/env bash

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

# teardown.sh - remove everything bringup.sh created. Leaves the shared
# kind-registry container in place (it persists across runs), only detaching it
# from the rack networks so they can be deleted.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

# Don't abort on the first missing resource; teardown is best-effort.
set +e

log "deleting KIND clusters"
"${KIND}" delete cluster --name "${CLUSTER_A}"
"${KIND}" delete cluster --name "${CLUSTER_B}"
rm -f "${CLUSTER_A_KUBECONFIG}" "${CLUSTER_B_KUBECONFIG}"
rm -f "${REPO_ROOT}/.${CLUSTER_A}.created" "${REPO_ROOT}/.${CLUSTER_B}.created"

log "removing ToR containers"
docker rm -f "${TOR_A}" "${TOR_B}" >/dev/null 2>&1

log "detaching kind-registry from rack networks"
for net in "${RACK_A_NET}" "${RACK_B_NET}"; do
  docker network disconnect -f "${net}" kind-registry >/dev/null 2>&1
done

log "removing docker networks"
for net in "${RACK_A_NET}" "${RACK_B_NET}" "${FABRIC_NET}"; do
  docker network rm "${net}" >/dev/null 2>&1
done

log "teardown complete (kind-registry left running)"
