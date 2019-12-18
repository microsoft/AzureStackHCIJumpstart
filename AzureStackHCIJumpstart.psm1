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
        # Also destroys basedisk, domain controller, and vSwitch
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

    $LabConfig.VMs.Where{$_.Role -ne 'Domain Controller'} | ForEach-Object {
        $AzureStackHCIVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
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

        Write-Host " - Destroying vSwitch"
        Remove-VMSwitch "$($LabConfig.SwitchName)*" -Force -ErrorAction SilentlyContinue

        Write-Host " - Destroying BaseDisk at $VMPath "
        Remove-Item -Path "$VMPath\BaseDisk_*.vhdx" -Force -ErrorAction SilentlyContinue
    }

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

#region Testing

#Note: This needs testing; merge requires the disks to be offline but at this point they will be on
#      Alternatively, how will i get the ACL
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
        }
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob
#endregion

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
    $DCName = $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' }
    $DC     = Get-VM -VMName "$($LabConfig.Prefix)$($DCName.VMName)" -ErrorAction SilentlyContinue

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
#TODO: Can this be runspaced?
        $thisDomain = $LabConfig.DomainNetbiosName
        Invoke-Command -VMName $thisSystem -Credential $localCred -ScriptBlock {
            Add-Computer -ComputerName $using:thisSystem -LocalCredential $Using:localCred -DomainName $using:thisDomain -Credential $Using:VMCred -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        }
    }

    Write-Host 'Shutting down VMs for Merge'
    Reset-AzStackVMs -Stop -VMs $AllVMs

    Remove-Variable VHDXToConvert, BaseDiskPath -ErrorAction SilentlyContinue

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
        }
    }

    Get-RSJob | Wait-RSJob
    Get-RSJob | Remove-RSJob

    Write-Host "Completed Environment Setup"

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

    $AzureStackHCIVMs = @()
    $LabConfig.VMs.Where{$_.Role -eq 'AzureStackHCI'} | ForEach-Object {
        $AzureStackHCIVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    # Most of these actions require the VMs to be shutdown
    Reset-AzStackVMs -Shutdown -VMs $AzureStackHCIVMs

    # If shutdown failed/timed out, stop the VMs
    Reset-AzStackVMs -Stop -VMs $AzureStackHCIVMs

    # Cleanup; Make sure nesting is enabled; Remove existing drives (except OS); Remove existing NICs (except OS)
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

            if ($thisSCSIController.ControllerNumber -ne 0) { Remove-VMScsiController -VMName $thisVM.VMName -ControllerNumber 1 }
        }

        Write-Host "Removing virtual adapters from: $($thisVM.VMName)"
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

            0..($theseSCMDrives.Count - 1) | ForEach-Object { New-VHD -Path "$SCMPath\$($thisVM.Name)-SCM-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null }

            0..($theseSCMDrives.Count - 1) | ForEach-Object {
                #Note: Keep this separate to avoid disk creation race

                Write-Host "`t Attaching SCM Drive from: $($SCMPath)\$($thisVM.Name)-SCM-$_.VHDX"
                Add-VMHardDiskDrive -VMName $thisVM.Name -Path "$SCMPath\$($thisVM.Name)-SCM-$_.VHDX" -ControllerType SCSI -ControllerNumber 1 -ControllerLocation $_ -ErrorAction SilentlyContinue | Out-Null
            }
        }

        Write-Host "`n Creating SSD Drives for $($thisVM.Name)"
        $theseSSDDrives | ForEach-Object {
            $thisDrive = $_

            0..($theseSSDDrives.Count - 1) | ForEach-Object { New-VHD -Path "$SSDPath\$($thisVM.Name)-SSD-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null }

            0..($theseSSDDrives.Count - 1) | ForEach-Object {
                #Note: Keep this separate to avoid disk creation race

                Write-Host "`t Attaching SSD Drive from: $($SSDPath)\$($thisVM.Name)-SSD-$_.VHDX"
                Add-VMHardDiskDrive -VMName $thisVM.Name -Path "$SSDPath\$($thisVM.Name)-SSD-$_.VHDX" -ControllerType SCSI -ControllerNumber 2 -ControllerLocation $_ -ErrorAction SilentlyContinue | Out-Null
            }
        }

        Write-Host "`n Creating HHD Drives for $($thisVM.Name)"
        $theseHDDDrives | ForEach-Object {
            $thisDrive = $_

            0..($theseHDDDrives.Count - 1) | ForEach-Object { New-VHD -Path "$HDDPath\$($thisVM.Name)-HDD-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null }

            0..($theseHDDDrives.Count - 1) | ForEach-Object {
                #Note: Keep this separate to avoid disk creation race

                Write-Host "`t Attaching HDD Drive from: $($HDDPath)\$($thisVM.Name)-HDD-$_.VHDX"
                Add-VMHardDiskDrive -VMName $thisVM.Name -Path "$HDDPath\$($thisVM.Name)-HDD-$_.VHDX" -ControllerType SCSI -ControllerNumber 3 -ControllerLocation $_ -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }

    Write-Host "`nBeginning Adapter configuration"
    #Setup guest adapters on the host
    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Write-Host "`t Creating adapters for $($thisVM.Name)"
        $theseAdapters = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.Adapters

        #Note: There shouldn't be any NICs in the system at this point, so just add however many you in $theseAdapters
        1..$theseAdapters.Count | Foreach-Object {
            Add-VMNetworkAdapter -VMName $thisVM.Name -SwitchName "$($LabConfig.SwitchName)*"
        }
    }

    #Note: Start to get a MAC on the vNICs to sort them in the future
    Reset-AzStackVMs -Start -VMs $AzureStackHCIVMs
    Reset-AzStackVMs -Stop -VMs $AzureStackHCIVMs

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        # Enable Device Naming; attach to the vSwitch; Trunk all possible vlans so that we can set a vlan inside the VM
        $vmAdapters = Get-VMNetworkAdapter -VMName $thisVM.Name | Sort-Object MacAddress

        $vmAdapters | ForEach-Object {
            Set-VMNetworkAdapter -VMNetworkAdapter $_ -DeviceNaming On
            Set-VMNetworkAdapterVlan -VMName $thisVM.Name -VMNetworkAdapterName $_.Name -Trunk -AllowedVlanIdList 1-4094 -NativeVlanId 0
        }

        Write-Host "`t Renaming vmNICs for propagation through to the $($thisVM.Name)"

        #Note: Naming the first 2 Mgmt for easy ID. This can be updated; just trying to keep it simple
        $AdapterCount = 1
        foreach ($NIC in ($vmAdapters | Select-Object -First 2)) {
            Rename-VMNetworkAdapter -VMNetworkAdapter $NIC -NewName "Mgmt0$AdapterCount"

            $AdapterCount ++
        }

        $AdapterCount = 0
        foreach ($NIC in ($vmAdapters | Select-Object -Skip 2)) {
            if ($AdapterCount -eq 0) { Rename-VMNetworkAdapter -VMNetworkAdapter $NIC -NewName 'Ethernet' }
            Else { Rename-VMNetworkAdapter -VMNetworkAdapter $NIC -NewName "Ethernet $AdapterCount" }

            $AdapterCount ++
        }
    }

    $AllVMs = @()
    $LabConfig.VMs | ForEach-Object {
        $AllVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    Write-Host "Starting VMs to continue configuration inside the guest"
    Reset-AzStackVMs -Start -VMs $AllVMs -Wait
    Remove-Variable AllVMs

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Write-Host "`t Removing any Ghost NICs in $($thisVM.Name)"
        Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
            $ghosts = Get-PnpDevice -class net | Where-Object Status -eq Unknown | Select-Object FriendlyName,InstanceId

            ForEach ($ghost in $ghosts) {
                $RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($ghost.InstanceId)"
                # $VerbosePreference = 'continue' - Use for testing
                Get-Item $RemoveKey | Select-Object -ExpandProperty Property | Foreach-Object { Remove-ItemProperty -Path $RemoveKey -Name $_ }
            }
        }

        #Note: Needs a clean reboot or the ghost NICs aren't removed; trying to shutdown instead because the reboot isn't working cleanly
        Write-Host "`t Rebooting to finalize ghost NIC removal"
        Reset-AzStackVMs -Shutdown -VMs $AzureStackHCIVMs.Where{$_.Name -eq $thisVM.Name} -Wait
        Reset-AzStackVMs -Start -VMs $AzureStackHCIVMs.Where{$_.Name -eq $thisVM.Name} -Wait

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
            Foreach ($vmNIC in $RenameVMNic) {
                #$VerbosePreference = 'continue' - Use for testing
                #Write-Host "`t`t`t NIC being renamed: $($vmNIC.name)"
                #Write-Host "`t`t`t`t New NIC Name: $($vmNIC.DisplayValue)"
                Rename-NetAdapter -Name $vmNIC.Name -NewName "$($vmNIC.DisplayValue)"
            }
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

        $theseSCMDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.SCMDrives.Size / 1GB
        $theseSSDDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.SSDDrives.Size / 1GB
        $theseHDDDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.HDDDrives.Size / 1GB

        Write-Host "Setting media type for the disks"
        Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
            Get-PhysicalDisk | Where-Object Size -eq $using:theseSCMDrivesSize | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "PMEM$($_.DeviceID)" -MediaType SCM
            }

            Get-PhysicalDisk | Where-Object Size -eq $using:theseSSDDrivesSize | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "SSD$($_.DeviceID)" -MediaType SSD
            }

            Get-PhysicalDisk | Where-Object Size -eq $using:theseHDDDrivesSize | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "HDD$($_.DeviceID)" -MediaType HDD
            }
        }

        Write-Host "Enabling SMB-in and Echo-in firewall rules"
        Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
            Get-NetFirewallRule -DisplayName "*File and Printer Sharing (Echo Request*In)" | Enable-NetFirewallRule
            Get-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" | Enable-NetFirewallRule
        }
    }

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
    Copy-Item -Path "$here\helpers\ModulesTillPublishedonGallery\PoshRSJob" -Recurse -Destination "C:\Program Files\WindowsPowerShell\Modules\PoshRSJob" -Container -ErrorAction SilentlyContinue
    Import-Module -Name PoshRSJob -Force -Global -ErrorAction SilentlyContinue

    Get-ChildItem "$here\helpers\ModulesTillPublishedonGallery" -Exclude PoshRSJob | foreach-Object {
        $thisModule = $_
        $path = $_.FullName
        $destPath = "C:\Program Files\WindowsPowerShell\Modules\$_"

        start-rsjob -Name "$thisModule-Modules" -ScriptBlock {
            Copy-Item -Path $using:path -Recurse -Destination $using:destPath -Container -Force -ErrorAction SilentlyContinue
        }

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
    Invoke-AzureStackHCILabVMCustomization

    $EndTime = Get-Date

    "Start Time: $StartTime"
    "End Time: $EndTime"
}

#TODO: Cleanup todos
#TODO: Test that labconfig is available and not malformed