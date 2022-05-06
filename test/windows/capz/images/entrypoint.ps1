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

$filePath = 'C:\exit-ebpfwin-container.txt'
while (-not (Test-Path -Path $filePath)) {
    ## Wait a specific interval
    Start-Sleep -Seconds 5
}

write-host "All done."
