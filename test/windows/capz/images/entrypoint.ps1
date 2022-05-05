if ($env:CONTAINER_SANDBOX_MOUNT_POINT) {
    $ns = $env:CONTAINER_SANDBOX_MOUNT_POINT
    write-host ("Install script is running in a HostProcess container. This sandbox mount point is {0}" -f $ns)
} else {
    throw "Install script is NOT running in a HostProcess container."
}

$EbpfWindowsZip = "ebpf-win-temp.zip"

Write-Host "Unzip ebpf-for-windows release..."
Expand-Archive -Force $EbpfWindowsZip c:\

cd c:\temp
Write-Host "Install ebpf-for-windows ..."
.\install-ebpf.bat

write-host "Sleep 5 minutes"
sleep 300
write-host "All done."
