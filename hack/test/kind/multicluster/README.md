# Two-cluster / two-ToR BGP harness (Phase 1)

Brings up two KIND clusters on two separate Docker networks — simulating two
on-prem racks — joined by a plain-BGP fabric of two `calico/bird` ToR routers.
The goal is to test Calico IPAM/route behavior during KubeVirt **decentralized
(cross-cluster) live migration** run on MockVirt, without nested virtualization.

## Why this shape

KubeVirt decentralized live migration has two cross-cluster channels: the QEMU
memory stream and the sync-controller gRPC. MockVirt's `FakeDomainManager`
**never opens the QEMU stream**, so the only cross-cluster traffic that matters
is the sync-controller gRPC (advertised as the sync-controller **pod IP**, port
9185). Phase 1 therefore only has to make **pod IPs routable between the two
clusters over BGP** — which is itself the Calico capability under test.

```
 rack-a 172.31.0.0/24        fabric 172.30.0.0/29        rack-b 172.32.0.0/24
  cluster-a AS65101           tor-a.2 <-eBGP-> .3 tor-b   cluster-b AS65102
  pods 10.244.0.0/16           (AS65001)   (AS65002)      pods 10.245.0.0/16
    nodes -eBGP-> tor-a                        tor-b <-eBGP- nodes
```

Each ToR peers eBGP with its cluster's Calico nodes and with the other ToR over
the fabric, re-advertising the remote cluster's pod routes with `next hop self`.

## Usage

```bash
# From anywhere in the repo:
make kind-multicluster-up      # or: hack/test/kind/multicluster/bringup.sh
make kind-multicluster-down    # or: hack/test/kind/multicluster/teardown.sh
```

Useful env vars (see `common.sh`):

| Var | Default | Purpose |
|-----|---------|---------|
| `SKIP_CALICO_BUILD` | `false` | Skip `make kind-build-images` and reuse existing local-registry images |
| `BIRD_IMAGE` | `calico/bird:v0.3.3-211-g9111ec3c-amd64` | ToR router image |
| `DEPLOY_MOCKVIRT` | `false` | Also deploy MockVirt + exchange CAs (see below) |
| `KUBEVIRT_REPO` | `~/go/src/github.com/kubevirt/kubevirt` | MockVirt checkout providing the manifests |

Kubeconfigs are written to `cluster-a-kubeconfig.yaml` / `cluster-b-kubeconfig.yaml`
in this directory.

## Verification (what bringup checks)

1. `calico-node` Ready + TigeraStatus Available on both clusters (via `deploy_resources.sh`).
2. BGP sessions Established on both ToRs (`birdcl show protocols`).
3. Cross-cluster routes present (`birdcl show route` shows the other cluster's pod CIDR).
4. A pod in cluster-a can ping a pod in cluster-b — the exact path the sync controller needs.

## MockVirt stage

`DEPLOY_MOCKVIRT=true` additionally deploys the MockVirt operator +
`kubevirt-cr-multicluster.yaml` (which enables `simulationMode` and the
`DecentralizedLiveMigration` feature gate) on both clusters and exchanges the
`kubevirt-ca` bundles.

### Image strategy: dev on Docker Hub, stable on quay/tigeradev

While the multi-cluster MockVirt code is unproven, build **all** images from the
current branch and push them to a personal Docker Hub repo — do NOT use the
stable `quay.io/tigeradev` images, and do NOT touch the `.semaphore` CI yet.
The CI push to `quay.io/tigeradev` (and any `.semaphore` change) happens only
once we're confident the branch works.

From the kubevirt checkout (branch `song-v1.8.1-mock-multi-cluster`):

```bash
docker login docker.io -u songtjiang           # personal Docker Hub
cd ~/go/src/github.com/kubevirt/kubevirt
DOCKER_PREFIX=docker.io/songtjiang DOCKER_TAG=mc-dev bash hack/ci-push-images.sh
```

This builds + pushes `docker.io/songtjiang/virt-{operator,api,controller,handler,launcher,synchronization-controller}:mc-dev`
and regenerates `_out/manifests/release/kubevirt-operator.yaml` pointing at those
images. The harness then consumes that generated manifest:

```bash
DEPLOY_MOCKVIRT=true make kind-multicluster-up
```

Override paths if needed via `MOCKVIRT_OPERATOR_MANIFEST` /
`MOCKVIRT_CR_MANIFEST` (see `common.sh`). The CR is registry-agnostic (config
only); the operator manifest is what carries the `docker.io/songtjiang` prefix.

## Phase 2 (later)

Replace the two `calico/bird` ToRs with FRR and enable EVPN-VXLAN on the
`tor-a <-> tor-b` link (Type-5 / L3VNI, symmetric IRB — the fit for Calico's
L3-routed model). The cluster-facing BGP and the MockVirt side stay unchanged.
