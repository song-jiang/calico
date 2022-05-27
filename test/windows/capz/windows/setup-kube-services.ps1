nssm.exe remove kubelet confirm

c:\\CalicoWindows\\kubernetes\\install-kube-services.ps1
Start-Sleep 10
Start-Service -Name kubelet
Start-Service -Name kube-proxy

& c:\k\kubectl.exe --kubeconfig=c:\k\config get pod -n demo -o wide
