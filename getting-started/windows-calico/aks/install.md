# Install Calico for Windows on AKS

This directory contains files to install Calico on AKS Windows nodes.

## Procedure

1. Create AKS cluster with `--network-plugin azure --network-policy calico`.

```
az aks create \
    --resource-group <your resource group> \
    --name <your cluster name> \
    --node-count 2 \
    --enable-addons monitoring \
    --generate-ssh-keys \
    --windows-admin-password $PASSWORD_WIN \
    --windows-admin-username azureuser \
    --vm-set-type VirtualMachineScaleSets \
    --service-principal <your service principal> \
    --client-secret <your client secret> \
    --network-plugin azure \
    --network-policy calico
```

2. Following https://docs.microsoft.com/en-us/azure/aks/windows-container-cli to add Windows Server node pool. Your may want to enable creatinga public-ip for Windows node if you want to connect it via RDP directly. 

3. Following https://docs.microsoft.com/en-us/azure/aks/rdp to setup RDP connection with your Windows server.

4. Get Cluster kubeconfig file and create cluster role for Calico on Windows node.
```
kubectl apply -f https://raw.githubusercontent.com/song-jiang/calico/song-aks/getting-started/windows-calico/aks/win-cluster-role.yaml
```

5. RDP into Windows node, download Calico installation script.
```
Invoke-WebRequest https://docs.projectcalico.org/scripts/install-calico-windows.ps1 -OutFile c:\install-calico-windows.ps1
```

6. Run Calico installation script.
```
c:\install-calico-windows.ps1
```

7. Verify Calico services are running.
```
PS C:\> Get-Service -Name CalicoNode

Status   Name               DisplayName
------   ----               -----------
Running  CalicoNode         Calico Windows Startup


PS C:\> Get-Service -Name CalicoFelix

Status   Name               DisplayName
------   ----               -----------
Running  CalicoFelix        Calico Windows Agent

```
