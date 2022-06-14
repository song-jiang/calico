
function CreateExternalNetwork()
{
    # Create a bridge to trigger a vSwitch creation. Do this only once
    Write-Host "`nStart creating vSwitch. Note: Connection may get lost for RDP, please reconnect...`n"
    while (!(Get-HnsNetwork | ? Name -EQ "External"))
    {
        if ($env:CALICO_NETWORKING_BACKEND -EQ "vxlan") {
            # FIXME Firewall rule port?
            New-NetFirewallRule -Name OverlayTraffic4789UDP -Description "Overlay network traffic UDP" -Action Allow -LocalPort 4789 -Enabled True -DisplayName "Overlay Traffic 4789 UDP" -Protocol UDP -ErrorAction SilentlyContinue
            $result = New-HNSNetwork -Type Overlay -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -SubnetPolicies @(@{Type = "VSID"; VSID = 9999; }) -AdapterName $vxlanAdapter -Verbose
        }
        else
        {
            $result = New-HNSNetwork -Type L2Bridge -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -Verbose
        }
        if ($result.Error -OR (!$result.Success)) {
            Write-Host "Failed to create network, retrying..."
            Start-Sleep 1
        } else {
            break
        }
    }
}

function EnableTestSigning()
{
  if (!(Test-Path c:\TestSigningOn))
  {
    Write-Host "Test signing on for the node..."
    Bcdedit.exe -set TESTSIGNING ON
    echo "Yes" > c:\TestSigningOn

    Write-Host "Reboot..."
    Restart-Computer
    Write-Host "Reboot done."
  } else {
    Write-Host "Test signing is already on."
  }
}

# Make sure the script is running in a HostProcess container.
if ($env:CONTAINER_SANDBOX_MOUNT_POINT) {
    $ns = $env:CONTAINER_SANDBOX_MOUNT_POINT
    write-host ("Install script is running in a HostProcess container. This sandbox mount point is {0}" -f $ns)
} else {
    throw "Install script is NOT running in a HostProcess container."
}

ipmo $ns\hns.psm1 -Force -DisableNameChecking

# This step would restart computer. Create external network after this.
if ($env:ENABLE_TEST_SIGNING) {
    EnableTestSigning
}

# Create external network as part of pre-install. This is to avoid network disruption on the follow-on ssh commands.
$env:CALICO_NETWORKING_BACKEND = "vxlan"
CreateExternalNetwork
Write-Host "External network done."


# Sleep until the container is required to exit explicitly. This is for dev only.
# TODO: If this container is running as an init container of a daemonset, 
# this section is not required.
$filePath = 'C:\exit-container.txt'
while (-not (Test-Path -Path $filePath)) {
    Start-Sleep -Seconds 30
}

write-host "All done."
exit 0
