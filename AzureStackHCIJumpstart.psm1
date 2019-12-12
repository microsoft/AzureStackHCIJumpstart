Function Approve-AzureStackHCILabHostState {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateSet('Host')]
        [String] $Test
    )

    $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path

    Switch ($Test) {
        'Host' {
            $ValidationResults = Invoke-Pester -Tag Host -Script "$here\tests\unit\unit.tests.ps1" -PassThru
            $ValidationResults | Select-Object -Property TagFilter, Time, TotalCount, PassedCount, FailedCount, SkippedCount, PendingCount | Format-Table -AutoSize

            If ($ValidationResults.FailedCount -ne 0) {
                Write-Warning 'Prerequisite checks on the host have failed. Please review the output to identify the reason for the failures'
                Break
            }
        }
    }
}

Function Remove-AzureStackHCILabEnvironment {
    # This function can be run independently of the others.
    param (
        # Also destroys basedisk, domain controller, and vSwitch
        [switch] $FireAndBrimstone
    )

    # Clean
    Clear-Host

    If ($FireAndBrimstone) { Write-Host 'Fire and Brimstone was specified -- This environment will self-destruct in T-5 seconds' ; Start-Sleep -Seconds 5 }

    # Reimporting in case this is run directly
    $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    Write-Host "Azure Stack HCI Jumpstart module is running from: $here"

    $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
    Import-Module $helperPath -Force

    $global:LabConfig = Get-LabConfig

    $AllVMs = @()
    $AzureStackHCIVMs = @()

    $LabConfig.VMs | ForEach-Object {
        $AllVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    $LabConfig.VMs.Where{$_.Role -ne 'Domain Controller'} | ForEach-Object {
        $AzureStackHCIVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    Reset-AzStackVMs -Shutdown -VMs $AllVMs

    If ($AzureStackHCIVMs -ne $null) {
        Write-Host "Destroying HCI VMs"
        Remove-VM -VM $AzureStackHCIVMs                   -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $AzureStackHCIVMs.Path -Recurse -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -Path "$VMPath\buildData" -Force -Recurse -ErrorAction SilentlyContinue

    If ($FireAndBrimstone) {
        Write-Host 'Fire and Brimstone mode'
        Write-Host " - Destroying Domain Controller"

        If ($AllVMs -ne $null) {
            Remove-VM -VM $AllVMs                   -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $AllVMs.Path -Recurse -Force -ErrorAction SilentlyContinue
        }

        Write-Host " - Destroying vSwitch"
        Remove-VMSwitch "$($LabConfig.SwitchName)*" -Force -ErrorAction SilentlyContinue

        Write-Host " - Destroying BaseDisk at $VMPath "
        Remove-Item -Path "$VMPath\BaseDisk_*.vhdx" -Force -ErrorAction SilentlyContinue
    }

    Write-Host 'Clean is finished...Exiting'
}
Function New-AzureStackHCILabEnvironment {
    # Hydrate base disk
    New-BaseDisk

    # Create Unattend File
    $TimeZone  = (Get-TimeZone).id
    Remove-Item -Path "$VMPath\buildData\Unattend.xml" -Force -ErrorAction SilentlyContinue

    New-UnattendFileForVHD -TimeZone $TimeZone -AdminPassword $LabConfig.AdminPassword -Path "$VMPath\buildData"

    # Update BaseDisk with Unattend and DSC
    Initialize-BaseDisk

    # Create Virtual Machines
    Add-LabVirtualMachines
    $AllVMs, $AzureStackHCIVMs = Get-LabVMs

    Write-Host "Starting All VMs" # Don't wait
    Reset-AzStackVMs -Start -VMs $AllVMs

    # Begin Reparenting Disks
    $AllVMs | ForEach-Object {
        $VHDXToConvert = $_ | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0
        $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath

        if ($BaseDiskPath -eq $VHDPath) {
            Write-Host "Beginning VHDX Reparenting for $($_.Name)"
            Move-ToNewParentVHDX -VM $_ -VHDXToConvert $VHDXToConvert
        }
    }

    # Rename Guests
    Wait-ForHeartbeatState -State On -VMs $AllVMs
    $LabConfig.VMs | Foreach-Object {
        $thisSystem = "$($LabConfig.Prefix)$($_.VMName)"
        Write-Host "Checking $thisSystem guest OS name prior to domain creation"

        $CurrentName = Invoke-Command -VMName $thisSystem -Credential $localCred -ScriptBlock { $env:ComputerName }

        if ($CurrentName -ne $thisSystem) {
            Write-Host "`t Renaming $thisSystem guest OS and rebooting prior to domain creation"

            Invoke-Command -VMName $thisSystem -Credential $localCred -ScriptBlock {
                Rename-Computer -NewName $using:thisSystem -Force -WarningAction SilentlyContinue
            }

            Reset-AzStackVMs -Restart -VMs $AllVMs.Where{$_.Name -eq $thisSystem}
        }
    }

    # Configure Lab Domain
    $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' } | Foreach-Object {
        $DC = Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    Write-Host "Configuring DC using DSC takes a while. Please be patient"

    Get-ChildItem "$VMPath\buildData\config" -Recurse -File | ForEach-Object {
        Copy-VMFile -Name $DC.Name -SourcePath $_.FullName -DestinationPath $_.FullName -CreateFullPath -FileSource Host -Force
    }

    Assert-LabDomain

    # Join lab VMs to domain
    $LabConfig.VMs.Where{ $_.Role -ne 'Domain Controller' } | Foreach-Object {
        $thisSystem = "$($LabConfig.Prefix)$($_.VMName)"
        Write-Host "Joining $thisSystem to domain"
#TODO: Only do this if not already joined
        $thisDomain = $LabConfig.DomainNetbiosName
        Invoke-Command -VMName $thisSystem -Credential $localCred -ScriptBlock {
            Add-Computer -ComputerName $using:thisSystem -LocalCredential $Using:localCred -DomainName $using:thisDomain -Credential $Using:VMCred -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        }
    }

    Write-Host 'Shutting down VMs for Merge'
    Reset-AzStackVMs -Shutdown -VMs $AllVMs

    Remove-Variable VHDXToConvert, BaseDiskPath -ErrorAction SilentlyContinue

    # Begin Merge
    $AllVMs | ForEach-Object {
        Remove-Variable VHDXToConvert, BaseDiskPath -ErrorAction SilentlyContinue
        $VHDXToConvert = $_ | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0
        $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath

        # Note: Get-VHD ParentPath always reports with 1 character if it's actually Null which is why we're doing this next monstrosity to figure out if it actually has a base disk or not
        if ($BaseDiskPath.Length -gt 0) {
            Write-Host "`t Beginning VHDX Merge for $($_.Name)"
            Convert-FromDiffDisk -VM $_ -VHDXToConvert $VHDXToConvert
        }
        Else { Write-Host "`t $($_.Name) VHDX has already been merged - backslash Ignore"}
    }

    Write-Host "Completed Environment Setup"
}

Function Invoke-AzureStackHCILabVMCustomization {
    $AzureStackHCIVMs = @()
    $LabConfig.VMs.Where{$_.Role -eq 'AzureStackHCI'} | ForEach-Object {
        $AzureStackHCIVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    # Most of these actions require the VMs to be shutdown
    Reset-AzStackVMs -Shutdown -VMs $AzureStackHCIVMs

    # Make sure nesting is enabled; Remove existing drives (except OS); Remove existing NICs (except OS)
    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_
        $NestedEnabled = (Get-VMProcessor -VMName $thisVM.VMName).ExposeVirtualizationExtensions

        if (-not ($NestedEnabled)) { Set-VMProcessor -VMName $thisVM.VMName -ExposeVirtualizationExtensions $true }

        Get-VMScsiController -VMName $thisVM.VMName | ForEach-Object {
            $thisSCSIController = $_

            $thisSCSIController.Drives | ForEach-Object {
                $thisVMDrive = $_

                if (-not ($_.ControllerNumber -eq 0 -and $_.ControllerLocation -eq 0)) {
                    $thisVMDrive | Remove-VMHardDiskDrive
                }
            }

            if ($thisSCSIController.ControllerNumber -ne 0) { Remove-VMScsiController -VMName $thisVM.VMName -ControllerNumber $thisSCSIController.ControllerNumber }
        }

        Write-Host "Remove virtual adapters from: $($thisVM.VMName)"
        Get-VMNetworkAdapter -VMName $thisVM.VMName | ForEach-Object {
            Remove-VMNetworkAdapter -VMName $thisVM.VMName
        }
    }

    # Create and attach new drives
    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_
        $thisVMPath = Join-path $thisVM.Path 'Virtual Hard Disks\DataDisks'
        Remove-Item -Path $thisVMPath -Recurse -Force -ErrorAction SilentlyContinue

        $SCMPath = New-Item -Path (Join-Path $thisVMPath 'SCM') -ItemType Directory -Force
        $SSDPath = New-Item -Path (Join-Path $thisVMPath 'SSD') -ItemType Directory -Force
        $HDDPath = New-Item -Path (Join-Path $thisVMPath 'HDD') -ItemType Directory -Force

        $theseSCMDrives = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.SCMDrives
        $theseSSDDrives = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.SSDDrives
        $theseHDDDrives = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.HDDDrives

        Write-Host "`n `nCreating drives for $($thisVM.Name)"

        # After Lab Environment is deployed, there should be 1 SCSI controller for the OSD. This step will add 3 more. If this gets messed up re-run lab environment setup.
        Write-Host "Creating SCSI Controllers for $($thisVM.Name)"
        1..3 | Foreach-Object { Add-VMScsiController -VMName $thisVM.Name -ErrorAction SilentlyContinue }

        Write-Host "Creating SCM Drives for $($thisVM.Name)"
        $theseSCMDrives | ForEach-Object {
            $thisDrive = $_

            0..($theseSCMDrives.Count - 1) | ForEach-Object { New-VHD -Path "$SCMPath\$($thisVM.Name)-SCM-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue }

            0..($theseSCMDrives.Count - 1) | ForEach-Object {
                #Note: Keep this separate to avoid disk creation race

                Write-Host "`t Attaching SCM Drive from: $($SCMPath)\$($thisVM.Name)-SCM-$_.VHDX"
                Add-VMHardDiskDrive -VMName $thisVM.Name -Path "$SCMPath\$($thisVM.Name)-SCM-$_.VHDX" -ControllerType SCSI -ControllerNumber 1 -ControllerLocation $_ -ErrorAction SilentlyContinue
            }
        }

        Write-Host "`n Creating SSD Drives for $($thisVM.Name)"
        $theseSSDDrives | ForEach-Object {
            $thisDrive = $_

            0..($theseSSDDrives.Count - 1) | ForEach-Object { New-VHD -Path "$SSDPath\$($thisVM.Name)-SSD-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue }

            0..($theseSSDDrives.Count - 1) | ForEach-Object {
                #Note: Keep this separate to avoid disk creation race

                Write-Host "`t Attaching SSD Drive from: $($SSDPath)\$($thisVM.Name)-SSD-$_.VHDX"
                Add-VMHardDiskDrive -VMName $thisVM.Name -Path "$SSDPath\$($thisVM.Name)-SSD-$_.VHDX" -ControllerType SCSI -ControllerNumber 2 -ControllerLocation $_ -ErrorAction SilentlyContinue
            }
        }

        Write-Host "`n Creating HHD Drives for $($thisVM.Name)"
        $theseHDDDrives | ForEach-Object {
            $thisDrive = $_

            0..($theseHDDDrives.Count - 1) | ForEach-Object { New-VHD -Path "$HDDPath\$($thisVM.Name)-HDD-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue }

            0..($theseHDDDrives.Count - 1) | ForEach-Object {
                #Note: Keep this separate to avoid disk creation race

                Write-Host "`t Attaching HDD Drive from: $($HDDPath)\$($thisVM.Name)-HDD-$_.VHDX"
                Add-VMHardDiskDrive -VMName $thisVM.Name -Path "$HDDPath\$($thisVM.Name)-HDD-$_.VHDX" -ControllerType SCSI -ControllerNumber 3 -ControllerLocation $_ -ErrorAction SilentlyContinue
            }
        }
    }

    #Setup guest adapters on the host
    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Write-Host "`n `nCreating adapters for $($thisVM.Name)"

        $theseAdapters = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.Adapters

        # Make sure VMs have 5 NICs - 1 Mgmt NIC and 4 NICs for other stuff - if more than 5 NICs exist, they will not be removed
        if ($thisVM.NetworkAdapters.Count -lt 5) {
            ($thisVM.NetworkAdapters.Count + 1)..5 | ForEach-Object {
                Add-VMNetworkAdapter -VMName $thisVM.Name -SwitchName $HostVMSwitchName
            }
        }

        # Enable Device Naming; attach to the vSwitch; Trunk all possible vlans so that we can set a vlan inside the VM
        $vmAdapters = Get-VMNetworkAdapter -VMName $thisVM.Name | Sort-Object MacAddress
        $vmAdapters | ForEach-Object {
            Set-VMNetworkAdapter -VMNetworkAdapter $_ -DeviceNaming On
            Connect-VMNetworkAdapter -VMNetworkAdapter $_ -SwitchName $HostVMSwitchName
            Set-VMNetworkAdapterVlan -VMName $vmAdapters.VMName -VMNetworkAdapterName $NIC.Name -Trunk -AllowedVlanIdList 1-4094 -NativeVlanId 0
        }

        # Rename adapters in Hyper-V so this will propagate through into the Guest
        Rename-VMNetworkAdapter -VMNetworkAdapter ($vmAdapters | Select-Object -first 1) -NewName 'Mgmt01'

        $Count = 0
        foreach ($NIC in ($vmAdapters | Select-Object -Skip 1)) {
            if ($Count -eq 0) { Rename-VMNetworkAdapter -VMNetworkAdapter $NIC -NewName 'Ethernet' }
            Else { Rename-VMNetworkAdapter -VMNetworkAdapter $NIC -NewName "Ethernet $Count" }

            $Count = $Count + 1
        }
    }

    # Begin configuration in the VMs
    Reset-AzStackVMs -Start -

    # Cleanup ghost NICs in Guest
    $VMs | ForEach-Object {
        $thisVM = $_
        Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {

            $Devs = Get-PnpDevice -class net | Where-Object Status -eq Unknown | Select-Object FriendlyName,InstanceId

            ForEach ($Dev in $Devs) {
                $RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($Dev.InstanceId)"
                Get-Item $RemoveKey | Select-Object -ExpandProperty Property | Foreach-Object { Remove-ItemProperty -Path $RemoveKey -Name $_ }

                Write-Host "Removing: $RemoveKey"
            }
        }
    }

    # NIC Naming in Guest
    $VMs | ForEach-Object {
        Invoke-Command -VMName $_.Name -Credential $VMCred -ScriptBlock {
            $thisVM = $_

            # Rename NICs in Guest based on CDN name on Host
            $RenameVNic = Get-NetAdapterAdvancedProperty -DisplayName "Hyper-V Net*"

            Foreach ($vNIC in $RenameVNic) {
                # Set to temp name first in case there are conflicts
                Rename-NetAdapter -Name $Vnic.Name -NewName "$($vNIC.DisplayValue)_Temp"
            }

            $RenameVNic = Get-NetAdapterAdvancedProperty -DisplayName "Hyper-V Net*"

            Foreach ($vNIC in $RenameVNic) {
                Rename-NetAdapter -Name $Vnic.Name -NewName "$($vNIC.DisplayValue)"
            }
        }
    }

    # Modify Interface Description to replicate real NICs in Guest
    $VMs | ForEach-Object {
        Invoke-Command -VMName $_.Name -Credential $VMCred -ScriptBlock {
            $interfaces = Get-NetAdapter

            foreach ($interface in $interfaces) {

                Switch -Wildcard ($interface.Name) {
                    'Mgmt01' {
                        Get-ChildItem -Path 'HKLM:\SYSTEM\ControlSet001\Enum\VMBUS' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            $psPath = $_.PSPath
                            $temp = Get-ItemProperty -Path $PsPath -Name 'FriendlyName' -ErrorAction SilentlyContinue |
                                        Where-Object FriendlyName -eq ($interface.InterfaceDescription) -ErrorAction SilentlyContinue

                            if ($null -ne $temp) {
                                $ThisInterface = $temp
                                Set-ItemProperty -Path $ThisInterface.PSPath -Name FriendlyName -Value 'Intel(R) Gigabit I350-t rNDC'
                            }

                            $thisInterface = $null
                        }
                    }

                    'Ethernet*' {
                        Get-ChildItem -Path 'HKLM:\SYSTEM\ControlSet001\Enum\VMBUS' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            $psPath = $_.PSPath
                            $friendlyPath = Get-ItemProperty -Path $PsPath -Name 'FriendlyName' -ErrorAction SilentlyContinue |
                                                Where-Object FriendlyName -eq ($interface.InterfaceDescription) -ErrorAction SilentlyContinue

                            if ($null -ne $friendlyPath) {
                                $intNum = $(($interface.Name -split ' ')[1])

                                if ($null -eq $intNum) {
                                    $ThisInterface = $friendlyPath
                                    Set-ItemProperty -Path $ThisInterface.PSPath -Name FriendlyName -Value "QLogic FastLinQ QL41262"
                                }
                                Else {
                                    $ThisInterface = $friendlyPath
                                    Set-ItemProperty -Path $ThisInterface.PSPath -Name FriendlyName -Value "QLogic FastLinQ QL41262 #$intNum"
                                }

                                $intNum = $null
                            }

                            $thisInterface = $null
                        }
                    }
                }
            }
        }
    }

    # Set Media Type for drives and rename
    $VMs | ForEach-Object {
        Invoke-Command -VMName $_.Name -Credential $VMCred -ScriptBlock {
            Get-PhysicalDisk | Where-Object Size -eq 32GB | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "PMEM$($_.DeviceID)" -MediaType SCM
            }

            Get-PhysicalDisk | Where-Object Size -eq 256GB | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "SSD$($_.DeviceID)" -MediaType SSD
            }

            Get-PhysicalDisk | Where-Object Size -eq 1TB | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "HDD$($_.DeviceID)" -MediaType HDD
            }
        }
    }
}


Function Initialize-AzureStackHCILabOrchestration {
<#
    .SYNOPSIS
        Run this to orchestrate the entire setup of the Azure Stack HCI lab environment

    .DESCRIPTION
        This module will help you deploy the Azure Stack HCI lab environment. This is not intended for production deployments.

        This script will:
        - Deploy the lab environment VMs
        - Create the AD Domain
        - Create additional VMs for Azure Stack HCI and Windows Admin Center
        - Configure the VMs

        Note: This function only calls exported functions

    .PARAMETER LabDomainName
        This is the domain name for the lab environment (will be created)

    .PARAMETER LabAdmin
        The domain admin username for the LabDomainName domain

    .PARAMETER LabPassword
        The plaintext password to be used for the LabAdmin account

    .PARAMETER HostVMSwitchName
        The name of the host virtual switch to attach lab VMs to

    .EXAMPLE
        TODO: Create Example

    .NOTES
        Author: Microsoft Azure Stack HCI vTeam

        Please file issues on GitHub @ GitHub.com/Microsoft/AzureStackHCIJumpstart

    .LINK
        More projects : https://aka.ms/HCI-Deployment
        Email Address : TODO
#>
    Clear-Host

    $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    Write-Host "Azure Stack HCI Jumpstart module is running from: $here"

    $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
    Import-Module $helperPath -Force

    $global:LabConfig = Get-LabConfig

# Check that the host is ready with approve host state
    Approve-AzureStackHCILabHostState -Test Host

# Initialize lab environment
    #New-AzureStackHCILabEnvironment

# Invoke VMs with appropriate configurations
    Invoke-AzureStackHCILabVMCustomization
}

#TODO: Add logging to Restart and shutdown for Reset-AzStackVM
#TODO: Cleanup todos
#TODO: Add WAC System