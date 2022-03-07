## Windows FV infrastructure
This directory contains scripts and manifests to setup Windows FV infrastructure.

### Steps
1. Export Environment variables. See example below:
```
export CLUSTER_NAME_CAPZ="win-capz"
export AZURE_LOCATION="westuk"
export KUBE_VERSION="1.23.3"

# run "az ad sp list --spn your-client-id" to get information.
export AZURE_SUBSCRIPTION_ID="<your subscription id>"

# Create an Azure Service Principal and paste the output here
export AZURE_TENANT_ID="<your tenant id>"
export AZURE_CLIENT_ID="<your client id>"
export AZURE_CLIENT_SECRET="<your client secrect>"
```

2. Create an azure cluster with 2 Linux nodes and 2 Windows nodes.
```
make create-cluster
```

3. Install Calico
```
make install-calico
```

To access your cluster, run `kubectl --kubeconfig=./kubeconfig ...`

### Access Linux or Windows nodes
```
make generate-helpers
```
Helper scripts which can be used to ssh or scp into each node are generated. See individual script for details.

### Cleanup
```
make delete-cluster
```
