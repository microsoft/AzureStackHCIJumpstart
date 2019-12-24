Function Approve-AzureStackHCILabState {
    param(
        [Parameter(Mandatory=$True)]
        [ValidateSet('Host', 'Lab')]
        [String] $Test
    )

    $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path

    Switch ($Test) {
        'Host' {
            $ValidationResults = Invoke-Pester -Tag Host -Script "$here\tests\unit\AzureStackHCILabState.unit.tests.ps1" -PassThru
            $ValidationResults | Select-Object -Property TagFilter, Time, TotalCount, PassedCount, FailedCount, SkippedCount, PendingCount | Format-Table -AutoSize

            If ($ValidationResults.FailedCount -ne 0) {
                Write-Error 'Prerequisite checks on the host have failed. Please review the output to identify the reason for the failures' -ErrorAction Stop
            }
        }

        'Lab' {
            $ValidationResults = Invoke-Pester -Tag Lab -Script "$here\tests\unit\AzureStackHCILabState.unit.tests.ps1" -PassThru
            $ValidationResults | Select-Object -Property TagFilter, Time, TotalCount, PassedCount, FailedCount, SkippedCount, PendingCount | Format-Table -AutoSize

            If ($ValidationResults.FailedCount -ne 0) {
                Write-Error 'Prerequisite checks for the lab environment have failed. Please review the output or rerun New-AzureStackHCILabEnvironment' -ErrorAction Stop
            }
        }
    }
}

Function Remove-AzureStackHCILabEnvironment {
    param (
        # Also destroys basedisk, domain controller, WAC system, and vSwitch
        [switch] $FireAndBrimstone
    )

    Clear-Host

    If ($FireAndBrimstone) { Write-Host 'Fire and Brimstone was specified -- This environment will self-destruct in T-5 seconds' ; Start-Sleep -Seconds 5 }

    # Reimporting in case this is run directly
    $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    Write-Host "Azure Stack HCI Jumpstart module is running from: $here"

    $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
    Import-Module $helperPath -Force

    if (-not ($labConfig)) { $global:LabConfig = Get-LabConfig }

    $AllVMs = @()
    $AzureStackHCIVMs = @()

    $LabConfig.VMs | ForEach-Object {
        $AllVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    $LabConfig.VMs.Where{$_.Role -eq 'AzureStackHCI'} | ForEach-Object {
        $AzureStackHCIVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    # Removing computer objects from AD (including CNO (LabConfig.Prefix)) if Fire and Brimstone was not specified
    $DomainController = $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' }
    $DCName = "$($LabConfig.Prefix)$($DomainController.VMName)"

    $AzureStackHCIVMs.Name, $($LabConfig.Prefix) | ForEach-Object {
        $thisVM = $_
        Invoke-Command -VMName $DCName -Credential $VMCred -ScriptBlock {
            #Note: Have to try/catch because remove-adcomputer won't shutup even with erroraction silentlycontinue
            try {
                [Console]::WriteLine("Removing $thisVM account from domain")
                Remove-ADComputer -Identity $thisVM -Confirm:$false
            }
            catch { [Console]::WriteLine("`t $thisVM account was not found") }
        } -ErrorAction SilentlyContinue
    }

    Reset-AzStackVMs -Stop -VMs $AllVMs

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

        Write-Host " - Destroying vSwitch and Nat"
        Remove-VMSwitch "$($LabConfig.Prefix)-$($LabConfig.SwitchName)*" -Force -ErrorAction SilentlyContinue
        Get-NetNat -Name "NAT-$($LabConfig.Prefix)-$($LabConfig.SwitchName)" | Remove-NetNat -Confirm:$false

        Write-Host " - Destroying BaseDisk at $VMPath "
        Remove-Item -Path "$VMPath\BaseDisk_*.vhdx" -Force -ErrorAction SilentlyContinue
    }

    Get-RSJob | Stop-RSJob   | Out-Null
    Get-RSJob | Remove-RSJob | Out-Null

    Write-Host 'Clean is finished...Exiting'
}

Function New-AzureStackHCILabEnvironment {
#region In case orchestration was not run
    if (-not ($here)) {
        $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
        if (-not ($isAdmin)) { Write-Error 'This must be run as an administrator - Please relaunch with administrative rights' -ErrorAction Stop }

        $StartTime = Get-Date
        $ranOOB = $true

        $global:here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    }

    if (-not (Get-Module -Name helpers)) {
        $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
        Import-Module $helperPath -Force
    }

    if (-not ($labConfig)) { $global:LabConfig = Get-LabConfig }
#endregion

    # Hydrate base disk - this is long and painful...
    New-BaseDisk

    # Update BaseDisk with buildData
    Initialize-BaseDisk

    #TODO: Start domain creation now but don't wait for it to finish, then create VMs, and reparent

    # Create Virtual Machines
    Add-LabVirtualMachines
    $global:AllVMs, $global:AzureStackHCIVMs = Get-LabVMs

    # Configure Lab Domain but don't wait for completion
    $DCName = $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' }
    $DC     = Get-VM -VMName "$($LabConfig.Prefix)$($DCName.VMName)" -ErrorAction SilentlyContinue

    # Start DC only; want this to startup as quickly as possible to begin creating the long running domain
    Write-Host "Starting DC VM"
    Reset-AzStackVMs -Start -VMs $DC -Wait

    # Now start all other VMs - Don't wait
    Write-Host "Starting All VMs"
    Reset-AzStackVMs -Start -VMs $AllVMs

    Write-Host "Configuring DC using DSC takes a while. Please be patient"
    Get-ChildItem "$VMPath\buildData\config" -Recurse -File | ForEach-Object {
        Copy-VMFile -Name $DC.Name -SourcePath $_.FullName -DestinationPath $_.FullName -CreateFullPath -FileSource Host -Force
    }

    # This runs asynchronously as nothing depends on this being complete at this point
    Assert-LabDomain

    # Begin long-running reparent task - runs async
    $AllVMs | ForEach-Object {
        $thisVM = $_

        Start-RSJob -Name "$($thisVM.Name)-Reparent" -ScriptBlock {
            $thisJobVM = $using:thisVM

            $VHDXToConvert = $thisJobVM | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0
            $ParentPath   = Split-Path -Path $VHDXToConvert.Path -Parent
            $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath

            if ($BaseDiskPath -eq $using:VHDPath) {
                [Console]::WriteLine("Copying VHDX base disk for reparenting on $($thisJobVM.Name)")

                $BaseLeaf = Split-Path $BaseDiskPath -Leaf
                $NewBasePath = Join-Path -Path $ParentPath -ChildPath $BaseLeaf
                Copy-Item -Path $BaseDiskPath -Destination $NewBasePath -InformationAction SilentlyContinue

                [Console]::WriteLine("`t Reparenting $($thisJobVM.Name) OSD to $NewBasePath")
                $VHDXToConvert | Set-VHD -ParentPath $NewBasePath -IgnoreIdMismatch
            }
        } | Out-Null
    }

    #Note: We've got time on our side here...Domain is being configured and reparenting is occuring which means we can get other stuff done while waiting.

    # Cleanup VM hardware (S2D disks and NICs) and recreate (later) in case this is not the first run
    [Console]::WriteLine("Cleaning up then re-adding VM hardware in case this is not the first run")
    Remove-AzureStackHCIVMHardware

    # Recreate NICs - Disks can't be done yet because adding new SCSI controllers require them to be offline
    New-AzureStackHCIVMAdapters

    # Cleanup Ghosts; System must be on but will require a full shutdown (not restart) to complete the removal so don't rename NICs yet.
    #Note: Ignore Loop count as this is the first start. Long startup is likely just sign of slow disks.
    Wait-ForHeartbeatState -State On -VMs $AllVMs -IgnoreLoopCount

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Write-Host "`t Removing any Ghost NICs in $($thisVM.Name)"
        Invoke-Command -VMName $thisVM.Name -Credential $localCred -ScriptBlock {
            $ghosts = Get-PnpDevice -class net | Where-Object Status -eq Unknown | Select-Object FriendlyName,InstanceId

            ForEach ($ghost in $ghosts) {
                $RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($ghost.InstanceId)"
                # $VerbosePreference = 'continue' - Use for testing
                Get-Item $RemoveKey | Select-Object -ExpandProperty Property | Foreach-Object { Remove-ItemProperty -Path $RemoveKey -Name $_ }
            }
        }
    }

    Wait-ForAzureStackHCIDomain

    # Join lab VMs to domain and enable firewall rules
    $LabConfig.VMs.Where{ $_.Role -ne 'Domain Controller' } | Foreach-Object {
        $thisSystem = "$($LabConfig.Prefix)$($_.VMName)"
        Write-Host "Joining $thisSystem to domain and enabling firewall rules (SMB-in and Echo-in)"

        Invoke-Command -VMName $thisSystem -Credential $localCred -ScriptBlock {
            if (-not (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
                $thisDomain = $($using:LabConfig.DomainNetbiosName)
                Add-Computer -DomainName $thisDomain -LocalCredential $Using:localCred -Credential $Using:VMCred -Force -WarningAction SilentlyContinue
            }

            Get-NetFirewallRule -DisplayName "*File and Printer Sharing (Echo Request*In)" | Enable-NetFirewallRule
            Get-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" | Enable-NetFirewallRule
        }
    }

    # Make sure all previous jobs have completed
    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob

    Write-Host 'Shutting down VMs for OSD Merge'
    Reset-AzStackVMs -Shutdown -VMs $AllVMs -Wait

    # Add S2D Disks needed for lab. System must be off to add SCSI controllers
    New-AzureStackHCIVMS2DDisks

    # Begin Merge
    $AllVMs | ForEach-Object {
        $thisVM = $_
        $BaseDiskACL = Get-ACL $VHDPath

        Start-RSJob -Name "$($thisVM.Name)-MergeAndACL" -ScriptBlock {
            $thisJobVM = $using:thisVM

            $VHDXToConvert = $thisJobVM | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0
            $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath

            # Note: Get-VHD ParentPath always reports with 1 character if it's actually Null which is why we're doing this next monstrosity to figure out if it actually has a base disk or not
            if ($BaseDiskPath.Length -gt 0) {
                [Console]::WriteLine("`t Beginning VHDX Merge for $($thisJobVM.Name)")

                Set-ACL  -Path $BaseDiskPath -AclObject $using:BaseDiskACL
                Set-ItemProperty -Path $BaseDiskPath -Name IsReadOnly -Value $false

                Merge-VHD -Path $VHDXToConvert.Path -DestinationPath $BaseDiskPath
                Remove-VMHardDiskDrive -VMName $thisJobVM.Name -ControllerNumber 0 -ControllerLocation 0 -ControllerType SCSI
                Add-VMHardDiskDrive -VM $thisJobVM -Path $BaseDiskPath -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -ErrorAction SilentlyContinue
            }
            Else { [Console]::WriteLine("`t $($thisJobVM.Name) VHDX has already been merged - backslash Ignore") }
        } | Out-Null
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob

    # Once merged, start VMs, then continue configuration inside the guest.
    # Previous tasks needed the shutdown/reboot anyway e.g. domain join and ghost NIC removal

    Reset-AzStackVMs -Start -VMs $AllVMs -Wait

    # Rename Adapters inside guest
    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Write-Host "`t Renaming NICs in the Guest based on the vmNIC name for easy ID"
        Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
            #$VerbosePreference = 'continue' - Use for testing
            $RenameVMNic = Get-NetAdapterAdvancedProperty -DisplayName "Hyper-V Net*"
            Foreach ($vNIC in $RenameVMNic) {
                #Note: Temp rename to avoid conflicts e.g. Ethernet should be adapter1 but is adapter2; renaming adapter2 first is necessary
                $Guid = $(((New-Guid).Guid).Substring(0,15))
                Rename-NetAdapter -Name $vNIC.Name -NewName $Guid
            }

            $RenameVMNic = Get-NetAdapterAdvancedProperty -DisplayName "Hyper-V Net*"
            Foreach ($vmNIC in $RenameVMNic) { Rename-NetAdapter -Name $vmNIC.Name -NewName "$($vmNIC.DisplayValue)" }
        }

        Write-Host "Modifying Interface Description to replicate real NICs in guest: $($thisVM.Name)"
        Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
            $interfaces = Get-NetAdapter | Sort-Object MacAddress

            foreach ($interface in $interfaces) {
                Switch -Wildcard ($interface.Name) {
                    'Mgmt01' {
                        Get-ChildItem -Path 'HKLM:\SYSTEM\ControlSet001\Enum\VMBUS' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            $psPath = $_.PSPath
                            $friendlyPath = Get-ItemProperty -Path $PsPath -Name 'FriendlyName' -ErrorAction SilentlyContinue |
                                                    Where-Object FriendlyName -eq ($interface.InterfaceDescription) -ErrorAction SilentlyContinue

                            if ($friendlyPath -ne $null) {
                                Set-ItemProperty -Path $friendlyPath.PSPath -Name FriendlyName -Value 'Intel(R) Gigabit I350-t rNDC'
                            }
                        }

                        Set-DnsClient -InterfaceAlias $interface.Name  -RegisterThisConnectionsAddress $true
                    }

                    'Mgmt02' {
                        Get-ChildItem -Path 'HKLM:\SYSTEM\ControlSet001\Enum\VMBUS' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            $psPath = $_.PSPath
                            $friendlyPath = Get-ItemProperty -Path $PsPath -Name 'FriendlyName' -ErrorAction SilentlyContinue |
                                                Where-Object FriendlyName -eq ($interface.InterfaceDescription) -ErrorAction SilentlyContinue

                            if ($friendlyPath -ne $null) {
                                Set-ItemProperty -Path $friendlyPath.PSPath -Name FriendlyName -Value 'Intel(R) Gigabit I350-t rNDC #2'
                            }

                            Set-DnsClient -InterfaceAlias $interface.Name  -RegisterThisConnectionsAddress $true
                        }
                    }

                    'Ethernet*' {
                        Get-ChildItem -Path 'HKLM:\SYSTEM\ControlSet001\Enum\VMBUS' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            $psPath = $_.PSPath
                            $friendlyPath = Get-ItemProperty -Path $PsPath -Name 'FriendlyName' -ErrorAction SilentlyContinue |
                                                Where-Object FriendlyName -eq ($interface.InterfaceDescription) -ErrorAction SilentlyContinue

                            if ($friendlyPath -ne $null) {
                                $intNum = $(($interface.Name -split ' ')[1])

                                if ($intNum -eq $null) {
                                    Set-ItemProperty -Path $friendlyPath.PSPath -Name FriendlyName -Value "QLogic FastLinQ QL41262"
                                }
                                Else {
                                    Set-ItemProperty -Path $friendlyPath.PSPath -Name FriendlyName -Value "QLogic FastLinQ QL41262 #$intNum"
                                }

                                $intNum = $null
                            }
                        }

                        Set-DnsClient -InterfaceAlias $interface.Name  -RegisterThisConnectionsAddress $false
                    }
                }
            }
        }
    }

    Write-Host 'Completed Environment Setup'

    if ($ranOOB) {
        Write-Host "`t Since this was run without orchestration, you may still need to customize using Invoke-AzureStackHCILabVMCustomization"
        $EndTime = Get-Date
        "Start Time: $StartTime"
        "End Time: $EndTime"
    }
}

Function Invoke-AzureStackHCILabVMCustomization {
#region In case orchestration was not run
    if (-not ($here)) {
        $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
        if (-not ($isAdmin)) { Write-Error 'This must be run as an administrator - Please relaunch with administrative rights' -ErrorAction Stop }

        $StartTime = Get-Date
        $ranOOB = $true

        $global:here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    }

    if (-not (Get-Module -Name helpers)) {
        $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
        Import-Module $helperPath -Force
    }

    if (-not ($labConfig)) { $global:LabConfig = Get-LabConfig }
#endregion

    # Check that the environment is good to go e.g. in case New-AzureStackHCILabEnvironment wasn't called
    Approve-AzureStackHCILabState -Test Lab

    # Stage testing and checkpoints
    $AllVMs | ForEach-Object {
        $thisVM = $_
        Start-RSJob -Name "$($thisVM.Name)-Stage 1 Checkpoints" -ScriptBlock {
            $thisJobVM = $using:thisVM

            [Console]::WriteLine("Verifying Starting checkpoint exists for: $($thisJobVM.Name)")
            While (-not (Get-VMSnapshot -VMName $thisJobVM.Name -Name Start)) {
                [Console]::WriteLine("`t Creating starting checkpoint for: $($thisJobVM.Name)")
                Checkpoint-VM -Name $thisJobVM.Name -SnapshotName 'Start'
            }
        } | Out-Null
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_
        Start-RSJob -Name "$($thisVM.Name)-Stage 1 Checkpoints for HCI VMs" -ScriptBlock {
            $thisJobVM = $using:thisVM

            [Console]::WriteLine("Checking and/or Installing Stage 1 Features for: $($thisJobVM.Name)")
            Invoke-Command -VMName $thisJobVM.Name -Credential $using:VMCred -ScriptBlock {
                Install-WindowsFeature -Name 'Bitlocker', 'Data-Center-Bridging', 'Failover-Clustering', 'FS-Data-Deduplication', 'Hyper-V', 'RSAT-AD-PowerShell' -IncludeManagementTools
            }
        } | Out-Null
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob

    #Note: Reboot to complete the installations, then wait again in case multiple reboots occur. Do sequential
    Write-Host "Restarting VMs following feature installation for stage 1 checkpoint"
    Reset-AzStackVMs -Restart -Wait -VMs $AzureStackHCIVMs
    Wait-ForHeartbeatState -State On -VMs $AzureStackHCIVMs

    # Reset Media Type following reboot
    Set-AzureStackHCIDiskMediaType

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_
        Start-RSJob -Name "$($thisVM.Name)-Stage 1 Checkpoints for HCI VMs" -ScriptBlock {
            $thisJobVM = $using:thisVM

            [Console]::WriteLine("`t Verifying Stage 1 checkpoint exists for: $($thisVM.Name)")
            While (-not (Get-VMSnapshot -VMName $thisVM.Name -Name 'Stage 1 Complete')) {
                [Console]::WriteLine("`t `tCreating Stage 1 checkpoint for: $($thisVM.Name)")
                Checkpoint-VM -Name $thisVM.Name -SnapshotName 'Stage 1 Complete'
            }
        }
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob

    # Do Stage 3 separately because we need all servers to be up and this run from one of the nodes
    $AzureStackHCIVMs | Select-Object -First 1 | ForEach-Object {
        $thisVM = $_

        [Console]::WriteLine("`t Preping Stage 3 - Clustering")
        [Console]::WriteLine("`t `t Running Test Cluster on: $($thisVM.Name)")
        Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock { Test-Cluster -Node $($Using:AzureStackHCIVMs.Name) -WarningAction SilentlyContinue | Out-Null }

        $DomainController = $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' }
        $DCName = "$($LabConfig.Prefix)$($DomainController.VMName)"
        $CNOExists = Invoke-Command -VMName $DCName -Credential $VMCred -ScriptBlock {
            #Note: Have to try/catch because remove-adcomputer won't shutup even with erroraction silentlycontinue
            try { Remove-ADComputer -Identity "$($using:LabConfig.Prefix)" -Confirm:$false }
            catch { [Console]::WriteLine("`t `t CNO was not found. Continuing with cluster creation)") }
        }

        if ($CNOExists) { Write-Host "AzStackHCI Computer account still exists - this should occur but the Cluster won't be able to be created...troubleshoot the removal of the account" }
        Else {
            Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
                #Note: Once Stage 2 is configured with separate L3 adapters, you may have to come back here and ignore networks for the CAP to be built on
                New-Cluster -Name "$($using:LabConfig.Prefix)" -Node $($Using:AzureStackHCIVMs.Name) -Force | Out-Null
            }
        }
    }

    # Need the DC now that there is an AD Object
    $AllVMs | ForEach-Object {
        $thisVM = $_
        Start-RSJob -Name "Stage 3 Checkpoint for: $($thisVM.Name)" -ScriptBlock {
            $thisJobVM = $using:thisVM

            [Console]::WriteLine("`t Creating Stage 3 checkpoint")
            While (-not (Get-VMSnapshot -VMName $thisJobVM.Name -Name 'Stage 3 Complete')) {
                Checkpoint-VM -Name $thisJobVM.Name -SnapshotName 'Stage 3 Complete'
            }
        }
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob

    # Apply Starting Checkpoint
    $AzureStackHCIVMs | ForEach-Object {
        Start-RSJob -Name "$($thisVM.Name)-Stage 1 Checkpoints" -ScriptBlock {
            $thisJobVM = $using:thisVM

            [Console]::WriteLine("Applying starting checkpoint for: $($thisJobVM.Name)")
            Restore-VMSnapshot -Name Start -VMName $thisJobVM.Name -Confirm:$false
        } | Out-Null
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob

    if ($ranOOB) {
        $EndTime = Get-Date
        "Start Time: $StartTime"
        "End Time: $EndTime"
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

    $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if (-not ($isAdmin)) { Write-Error 'This must be run as an administrator - Please relaunch with administrative rights' -ErrorAction Stop }

    $StartTime = Get-Date

    Clear-Host

    $global:here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    Write-Host "Azure Stack HCI Jumpstart module is running from: $here"

    #Note: These are required until this entire package is published in the PoSH gallery. Once completed, requiredmodules will be used in the manifest.
    Get-ChildItem "$here\helpers\ModulesTillPublishedonGallery" | Foreach-Object {
        Get-Module -Name $_.Name | Remove-Module -Force -ErrorAction SilentlyContinue
    }

    Write-Host "Importing Modules from: $here\helpers"
#region Temporary unti; added to posh gallery
    Copy-Item -Path "$here\helpers\ModulesTillPublishedonGallery\PoshRSJob" -Recurse -Destination "C:\Program Files\WindowsPowerShell\Modules\PoshRSJob" -Container -ErrorAction SilentlyContinue | Out-Null
    Import-Module -Name PoshRSJob -Force -Global -ErrorAction SilentlyContinue

    Get-ChildItem "$here\helpers\ModulesTillPublishedonGallery" -Exclude PoshRSJob | foreach-Object {
        $thisModule = $_
        $path = $_.FullName
        $destPath = "C:\Program Files\WindowsPowerShell\Modules\$_"

        Start-RSJob -Name "$thisModule-Modules" -ScriptBlock {
            Copy-Item -Path $using:path -Recurse -Destination $using:destPath -Container -Force -ErrorAction SilentlyContinue
        } | Out-Null

        Import-Module -Name $_ -Force -Global -ErrorAction SilentlyContinue
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob
#endregion

    $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
    Import-Module $helperPath -Force

    $global:LabConfig = Get-LabConfig

# Check that the host is ready with approve host state
    Approve-AzureStackHCILabState -Test Host

    # Initialize lab environment
    New-AzureStackHCILabEnvironment

# Invoke VMs with appropriate configurations
    #Invoke-AzureStackHCILabVMCustomization

    $EndTime = Get-Date

    "Start Time: $StartTime"
    "End Time: $EndTime"
}
#TODO: Cleanup todos
#TODO: Test that labconfig is available and not malformed