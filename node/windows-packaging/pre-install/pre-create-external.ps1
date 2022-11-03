# Copyright (c) 2022 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script removes HNS networks created by Calico and recreates an VXLAN external network.

$softwareRegistryKey = "HKLM:\Software\Tigera"
$calicoRegistryKey = $softwareRegistryKey + "\Calico"

function Get-LastBootTime()
{
    $bootTime = (Get-CimInstance win32_operatingsystem | select @{LABEL='LastBootUpTime';EXPRESSION={$_.lastbootuptime}}).LastBootUpTime
    if (($bootTime -EQ $null) -OR ($bootTime.length -EQ 0))
    {
        throw "Failed to get last boot time"
    }
 
    # This function is used in conjunction with Get-StoredLastBootTime, which
    # returns a string, so convert the datetime value to a string using the "general" standard format.
    return $bootTime.ToString("G")
}

function ensureRegistryKey()
{
    if (! (Test-Path $softwareRegistryKey))
    {
        New-Item $softwareRegistryKey
    }
    if (! (Test-Path $calicoRegistryKey))
    {
        New-Item $calicoRegistryKey
    }
}

function Get-StoredLastBootTime()
{
    try
    {
        return (Get-ItemProperty $calicoRegistryKey -ErrorAction Ignore).LastBootTime
    }
    catch
    {
        $PSItem.Exception.Message
    }
}

function Set-StoredLastBootTime($lastBootTime)
{
    ensureRegistryKey

    return Set-ItemProperty $calicoRegistryKey -Name LastBootTime -Value $lastBootTime
}

function RemoveAllNetworks()
{
    if ((Get-HNSNetwork | ? Type -NE nat))
    {
        Write-Host "First time Calico has run since boot up, cleaning out any old network state."
        Get-HNSNetwork | ? Type -NE nat | Remove-HNSNetwork
        do
        {
            Write-Host "Waiting for network deletion to complete."
            Start-Sleep 1
        } while ((Get-HNSNetwork | ? Type -NE nat))
    }
}

function EnsureExternalNetwork()
{
    param(
      [parameter(Mandatory=$false)] $NETWORK_BACKEND = "vxlan",
      # Network Adapter used on VXLAN, leave blank for primary NIC.
      [parameter(Mandatory=$false)] $VXLAN_ADAPTER = ""
    )

    # Create a bridge to trigger a vSwitch creation. Do this only once
    Write-Host "`nStart creating vSwitch $NETWORK_BACKEND. Note: Connection may get lost for RDP, please reconnect...`n"
    while (!(Get-HnsNetwork | ? Name -EQ "External"))
    {
        if ($NETWORKING_BACKEND -NE "l2bridge") {
            # FIXME Firewall rule port?
            New-NetFirewallRule -Name OverlayTraffic4789UDP -Description "Overlay network traffic UDP" -Action Allow -LocalPort 4789 -Enabled True -DisplayName "Overlay Traffic 4789 UDP" -Protocol UDP -ErrorAction SilentlyContinue
            $result = New-HNSNetwork -Type Overlay -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -SubnetPolicies @(@{Type = "VSID"; VSID = 9999; }) -AdapterName $VXLAN_ADAPTER -Verbose
        }
        else
        {
            $result = New-HNSNetwork -Type L2Bridge -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -Verbose
        }
        if ($result.Error -OR (!$result.Success)) {
            Write-Host "Failed to create network, retrying..."
            Start-Sleep 10
        } else {
            break
        }
    }
}

Invoke-WebRequest https://raw.githubusercontent.com/microsoft/SDN/0d7593e5c8d4c2347079a7a6dbd9eb034ae19a44/Kubernetes/windows/hns.psm1 -O c:\k\hns.psm1
ipmo c:\k\hns.psm1

$lastBootTime = Get-LastBootTime
Set-StoredLastBootTime $lastBootTime
Write-Host "Stored new lastBootTime $lastBootTime to avoid Calico recreating networks"

RemoveAllNetworks
EnsureExternalNetwork # This should run as the last command of the script

