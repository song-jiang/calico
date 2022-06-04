$Root="c:\\CalicoWindows"

# Use the calico-felix.exe under test. We need to replace the felix service
# using calico-node.exe.
cp c:\\k\\calico-felix.exe $Root
cp c:\\k\\restart-felix.ps1 $Root
(Get-Content $Root\felix\felix-service.ps1).replace(".\calico-node.exe -felix", ".\calico-felix.exe") | Set-Content $Root\felix\felix-service.ps1 -Force
