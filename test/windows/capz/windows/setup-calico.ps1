$env:CNI_BIN_DIR = "C:/opt/cni/bin"
$env:CNI_CONF_DIR = "C:/etc/cni/net.d"

c:\\k\\install-calico-windows.ps1 -KubeVersion $KubeVersion -ContainerdCniBinDir C:/opt/cni/bin -ContainerdCniConfDir C:/etc/cni/net.d

