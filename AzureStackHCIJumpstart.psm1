Function Get-AzureStackHCILabConfig {
    # This is the path where VMs will be created for the lab e.g. c:\DataStore\VMs (then \VM01 folder will be added below it)
    $global:VMPath = 'C:\DataStore\VMs'
    New-Item -Path $VMPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    $LabConfig = @{
        # Will be appended to every VM
        Prefix     = 'AzStackHCI'

        # Lab domain admin
        DomainAdminName   = 'Bruce'
        AdminPassword     = 'd@rkKnight!'

        # The FQDN of the lab domain to be created
        DomainName        = 'gotham.city'

        # This is the filepath to the ISO that will be used to deploy the lab VMs
        ServerISO   = 'C:\Datastore\19507.1000.191028-1403.rs_prerelease_SERVER_VOL_x64FRE_en-us.iso'

        #BaseVHDX    = 'C:\DataStore\CustomVHD\BaseDisk_19540_server_serverdatacenter_en-us_vl.vhdx'

        # This is the name of the internal switch to attach VMs to. This uses DHCP to assign VMs IPs and uses NAT to avoid taking over your network...
        # If the specified switch doesn't exist an Internal switch will be created AzureStackHCILab-Guid.
        #Note: Only /24 is supported right now.
        DHCPscope     = '10.0.0.0'

        SwitchName = 'SiteA'
        VMs = @()
    }

    1..4 | ForEach-Object {
        $LABConfig.VMs += @{
            VMName        = "0$_"

            # 'Role' should always be AzureStackHCI
            Role = 'AzureStackHCI'
            MemoryStartupBytes = 8GB

            SCMDrives = @{ Count = 2 ; Size  = 32GB  }
            SSDDrives = @{ Count = 4 ; Size  = 256GB }
            HDDDrives = @{ Count = 8 ; Size  = 1TB   }

            #TODO: Adding NIC Naming differently than Mgmt and Ethernet
            Adapters = @(
                #Note: Where/when needed, these will include a unique number to distinguish
                @{ InterfaceDescription = 'Intel(R) Gigabit I350-t rNDC'}
                @{ InterfaceDescription = 'Intel(R) Gigabit I350-t rNDC'}
                @{ InterfaceDescription = 'QLogic FastLinQ QL41262'}
                @{ InterfaceDescription = 'QLogic FastLinQ QL41262'}
                @{ InterfaceDescription = 'QLogic FastLinQ QL41262'}
                @{ InterfaceDescription = 'QLogic FastLinQ QL41262'}
            )
        }
    }

    # Specify WAC System; does not install WAC, just creates server. You will need to ManageAs in WAC due to known CredSSP Bug
    $LABConfig.VMs += @{
        VMName = 'WAC01'
        MemoryStartupBytes = 4GB

        # This should always be WAC
        Role = 'WAC'
    }

    $LABConfig.VMs += @{
        VMName        = 'DC01'
        MemoryStartupBytes = 2GB

        # This should always be Domain Controller - Do not change
        Role          = 'Domain Controller'
    }

    # No touchie! Required but no mods needed - Prep local and domain creds
    $LabConfig.DomainNetbiosName = ($LabConfig.DomainName.Split('.')[0])
    $global:pass   = ConvertTo-SecureString $($LabConfig.AdminPassword) -AsPlainText -Force
    $global:VMCred = New-Object System.Management.Automation.PSCredential ("$($LabConfig.DomainName)\$($LabConfig.DomainAdminName)", $pass)
    $global:localCred = New-Object System.Management.Automation.PSCredential ('.\Administrator', $pass)

    $LabConfig
}

Function Remove-AzureStackHCILabEnvironment {
    param (
        # Also destroys basedisk, domain controller, WAC system, and vSwitch
        [switch] $FireAndBrimstone
    )

    Clear-Host

    $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if (-not ($isAdmin)) { Write-Error 'This must be run as an administrator - Please relaunch with administrative rights' -ErrorAction Stop }


    If ($FireAndBrimstone) { Write-Host 'Fire and Brimstone was specified -- This environment will self-destruct in T-5 seconds' ; Start-Sleep -Seconds 5 }

    # Reimporting in case this is run directly
    $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    Write-Host "Azure Stack HCI Jumpstart module is running from: $here"

    $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
    Import-Module $helperPath -Force

    if (-not ($labConfig)) { $global:LabConfig = Get-AzureStackHCILabConfig }

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
        Get-NetNat -Name "NAT-$($LabConfig.Prefix)-$($LabConfig.SwitchName)" -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue

        Write-Host " - Destroying BaseDisk at $VMPath "
        Remove-Item -Path "$VMPath\BaseDisk_*.vhdx" -Force -ErrorAction SilentlyContinue
    }

    Get-RSJob | Stop-RSJob   | Out-Null
    Get-RSJob | Remove-RSJob | Out-Null

    Write-Host 'Clean is finished...Exiting'
}

Function Restore-AzureStackHCIStageSnapshot {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('0', '1', '3')]
        [Int32] $Stage
    )

    #TODO: Restore DC to stage 0 for stage 0 or 1 (includes domain join but not the cluster)
    #TODO: Restore DC to stage 3 for cluster including CNO
    Switch ($Stage) {
        0 {
            $AllVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Restoring starting checkpoint" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    [Console]::WriteLine("Restoring starting checkpoint for: $($thisJobVM.Name)")
                    Restore-VMSnapshot -Name Start -VMName $thisJobVM.Name -Confirm:$false
                } -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null
        }

        1 {
            $AzureStackHCIVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Restoring starting checkpoint" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    [Console]::WriteLine("Restoring Stage 1 checkpoint for: $($thisJobVM.Name)")
                    Restore-VMSnapshot -Name 'Stage 1 Complete' -VMName $thisJobVM.Name -Confirm:$false
                } -OutVariable +RSJob | Out-Null
            }

            #Note: DC does not have stage 1 snapshot so apply stage 0 to ensure that CNO from stage 3 is not in the directory
            $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' } | Foreach-Object { $DCName = "$($LabConfig.Prefix)$($_.VMName)" }

            $AllVMs.Where{ $_.Name -eq $DCName } | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Restoring starting checkpoint" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    [Console]::WriteLine("Restoring starting checkpoint for: $($thisJobVM.Name)")
                    Restore-VMSnapshot -Name 'Start' -VMName $thisJobVM.Name -Confirm:$false
                } -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null
        }

        3 {
            #TODO: This whole thing
            #Note: Need to restore the dc as well...
        }
    }
}

Function Initialize-AzureStackHCILabOrchestration {
<#
    .SYNOPSIS
        Run this to orchestrate the setup of the Azure Stack HCI lab environment

    .DESCRIPTION
        This module will help you deploy the Azure Stack HCI lab environment. This is not intended for production deployments.

        For more information, please see: gitHub.com/Microsoft/AzureStackHCIJumpstart

    .EXAMPLE
        For examples, please see: gitHub.com/Microsoft/AzureStackHCIJumpstart

    .NOTES
        Author: Microsoft Azure Stack HCI vTeam
        Please file issues on GitHub @ GitHub.com/Microsoft/AzureStackHCIJumpstart

    .LINK
        More projects : https://aka.ms/HCI-Deployment
        Email Address : HCI-Deployment@Microsoft.com
#>

    Clear-Host

    $global:here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    Write-Host "Azure Stack HCI Jumpstart module is running from: $here"
    New-Item "$here\timer.log" -ItemType File -Force -OutVariable logfile | Out-Null

    $StartTime = Get-Date
    "Start Time: $($StartTime.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname

    $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if (-not ($isAdmin)) { Write-Error 'This must be run as an administrator - Please relaunch with administrative rights' -ErrorAction Stop }

    #Note: These are required until this entire package is published in the PoSH gallery. Once completed, requiredmodules will be used in the manifest.
    Get-ChildItem "$here\helpers\ModulesTillPublishedonGallery" | Foreach-Object {
        Get-Module -Name $_.Name | Remove-Module -Force -ErrorAction SilentlyContinue
    }

#region Temporary until; added to posh gallery
    Write-Host "Importing Modules from: $here\helpers"
    Copy-Item -Path "$here\helpers\ModulesTillPublishedonGallery\PoshRSJob" -Recurse -Destination "C:\Program Files\WindowsPowerShell\Modules\PoshRSJob" -Container -ErrorAction SilentlyContinue | Out-Null
    Import-Module -Name PoshRSJob -Force -Global -ErrorAction SilentlyContinue

    Get-ChildItem "$here\helpers\ModulesTillPublishedonGallery" -Exclude PoshRSJob | foreach-Object {
        $thisModule = $_
        $path = $_.FullName
        $destPath = "C:\Program Files\WindowsPowerShell\Modules\"

        Start-RSJob -Name "$thisModule-Modules" -ScriptBlock {
            Copy-Item -Path $using:path -Recurse -Destination $using:destPath -Force
        } -OutVariable +RSJob | Out-Null

        Import-Module -Name $thisModule -Force -Global -ErrorAction SilentlyContinue
    }

    Wait-RSJob   $RSJob | Out-Null
    Remove-RSJob $RSJob | Out-Null
#endregion

    $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
    Import-Module $helperPath -Force

    $global:LabConfig = Get-AzureStackHCILabConfig

    $timer = Get-Date
    "Beginning Host Approval Time: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname
    # Check that the host is ready with approve host state
    Approve-AzureStackHCILabState -Test Host

    $timer = Get-Date
    "Completed Host Approval Time: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname
#region BaseDisk and VM Create
    # Hydrate base disk - this is long and painful...
    if ($LabConfig.ServerISO) {
        New-BaseDisk

        $timer = Get-Date
        "Completed base disk creation: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname
    }

    # Update BaseDisk with buildData
    Initialize-BaseDisk

    $timer = Get-Date
    "Completed base disk initialization: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname

    # Create Virtual Machines
    Add-LabVirtualMachines
    $global:AllVMs, $global:AzureStackHCIVMs = Get-LabVMs

    $timer = Get-Date
    "Completed VM Creation: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname
#endregion

#region VM Startup
    # Start DC only; want this to startup as quickly as possible to begin creating the long running domain
    Write-Host "Starting DC VM"

    $DCName = $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' }
    $DC     = Get-VM -VMName "$($LabConfig.Prefix)$($DCName.VMName)" -ErrorAction SilentlyContinue
    Reset-AzStackVMs -Start -VMs $DC -Wait

    $timer = Get-Date
    "Completed Domain Controller VM initialization: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname

    #Note: Unattend file renames the VM on first startup; now we need to ensure that the machine has been rebooted prior to beginning DC Promotion
    Write-Host 'Renaming Host and Prepping for DC Promotion'
    Register-AzureStackHCIStartupTasks -VMs $DC

    Invoke-Command -VMName $DC.Name -Credential $localCred -ScriptBlock {
        Start-ScheduledTask -TaskName 'Azure Stack HCI Startup settings'
    }

    do {
        Get-ChildItem "$VMPath\buildData\config" -Recurse -File | ForEach-Object {
            Copy-VMFile -Name $DC.Name -SourcePath $_.FullName -DestinationPath $_.FullName -CreateFullPath -FileSource Host -Force
        }

        [Console]::WriteLine("`t Checking if reboot is needed due to hostname change prior to DC Promotion")
        Remove-Variable BuildDataExists, RebootIsNeeded -ErrorAction SilentlyContinue

        $BuildDataExists, $RebootIsNeeded = Invoke-Command -VMName $DC.Name -Credential $localCred -ScriptBlock {
            $thisDC = $using:DC

            $metaConfig = Test-Path C:\DataStore\VMs\buildData\config\localhost.mof -ErrorAction SilentlyContinue
            $DCConfig   = Test-Path C:\DataStore\VMs\buildData\config\localhost.meta.mof -ErrorAction SilentlyContinue
            $BuildDataExists = $metaConfig -and $DCConfig

            do {
                Rename-Computer -NewName $thisDC.Name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                #Note: ActiveName will display the computer name before a reboot; ComputerName is the name it will be after a reboot; VMName is the name of the vm in Hyper-V
                #      Goal of this is to detect if the machine needs a reboot to apply the name change, which needs to be done before DC Promotion
                #      We loop to give the startup script/rename process a few seconds to complete
                $ActiveName     = (Get-Itemproperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue).ComputerName
                $ComputerName   = (Get-Itemproperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue).ComputerName
                $VMName         = (Get-Itemproperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' -ErrorAction SilentlyContinue).VirtualMachineName

                # If we couldn't get values from VMName or Computername, assign an arbitrary value to VMName so this evaluates as false and repeats the loop
                if ($VMName -eq $null -or $ComputerName -eq $Null) { $VMName = (New-Guid).Guid }
            } until ($VMName -eq $ComputerName)

            $RebootIsNeeded = $ActiveName -ne $ComputerName
            Return $BuildDataExists, $RebootIsNeeded
        }

        [Console]::WriteLine("`t Reboot is needed: $RebootIsNeeded")
        if ($RebootIsNeeded) { Reset-AzStackVMs -VMs $DC -Restart -Wait }
    } Until (($BuildDataExists -eq $true) -and ($RebootIsNeeded -eq $false))

    $timer = Get-Date
    "Completed Domain Controller rename, reboot, scheduled tasks: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname
#endregion

#region Domain Creation and VM online customization

    $timer = Get-Date
    "Initializing domain creation: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname
    # This runs asynchronously as nothing depends on this being complete at this point
    Write-Host "`t Configuring Domain Controller takes a while. Please be patient"
    Assert-LabDomain

    $timer = Get-Date
    "Initializing non-Domain controller VMs: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname

    #Note: We've got time on our side here...Domain is being configured and reparenting is occuring which means we can get other stuff done while waiting.
    # Now start all other VMs - Don't wait for completion, but stagger startup for hosts with slow disks if the OSD is the default size (4096KB) indicating it's not started before.
    Write-Host "Starting All VMs - Will stagger if this is first startup"

    $VMCounter = 0
    $AllVMs.Where{ $_.Role -ne 'Domain Controller' } | Foreach-Object {
        $thisVM = $_
        $VMCounter ++

        <# Get OSD VHD file length. If greater than specified size (default size is 4MB) then machine has started up previously and we can start the next VM
            If this is the first startup, this delay will let each individual VM startup faster since there will likely be less disk churn
            In testing this allowed startup to occur much more rapidly and on low memory machines, allows dynamic memory to reclaim memory #>

        #Note: Don't open the console until a desktop is seen. On first logon, a bunch of things happen. If you open before that, it won't occur
        Write-host "`t Starting VM $($thisVM.Name)"
        Reset-AzStackVMs -Start -VMs $thisVM

        # If there are only 2 VMs left to start, just keep going...no more delays, get on with it.
        If (($VMCounter - 2) -lt $AllVMs.Count) {
            $thisVMOSDLength = 4MB
            While ($thisVMOSDLength -le 750MB) {
                $thisVMOSDLength = (Get-ChildItem -Path ($thisVM | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0).Path).Length
                Start-Sleep -Seconds 5
            }
        }
    }

    $timer = Get-Date
    "Completed non-domain controller VMs initialization: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname

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
        } -OutVariable +RSJob | Out-Null
    }

    $timer = Get-Date
    "Completed VHDX Reparenting: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname

    # Cleanup VM hardware (S2D disks and NICs) and recreate (later) in case this is not the first run
    [Console]::WriteLine("Cleaning up then re-adding VM hardware in case this is not the first run")
    Remove-AzureStackHCIVMHardware

    # Recreate NICs - Disks can't be done yet because adding new SCSI controllers require them to be offline
    New-AzureStackHCIVMAdapters

    $timer = Get-Date
    "Completed VMHardware removal and adapter reinitialization: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname

    # Cleanup Ghosts; System must be on but will require a full shutdown (not restart) to complete the removal so don't rename NICs yet.
    Wait-ForHeartbeatState -State On -VMs $AllVMs
    Register-AzureStackHCIStartupTasks -VMs $AllVMs.Where{$_.Name -ne $DC.Name}

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Write-Host "`t Removing any Ghost NICs in $($thisVM.Name)"
        Invoke-Command -VMName $thisVM.Name -Credential $localCred -ScriptBlock {
            $ghosts = Get-PnpDevice -class net | Where-Object Status -eq Unknown | Select-Object FriendlyName,InstanceId

            ForEach ($ghost in $ghosts) {
                $RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($ghost.InstanceId)"
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
                # Make sure you get an IP now that DHCP has been configured
                ipconfig /release | Out-Null
                ipconfig /renew   | Out-Null

                # Join computer to domain
                $thisDomain = $($using:LabConfig.DomainNetbiosName)
                Add-Computer -NewName $using:thisSystem -DomainName $thisDomain -LocalCredential $Using:localCred -Credential $Using:VMCred -Force -WarningAction SilentlyContinue
            }

            Get-NetFirewallRule -DisplayName "*File and Printer Sharing (Echo Request*In)" | Enable-NetFirewallRule
            Get-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" | Enable-NetFirewallRule
        }
    }

    # Make sure all previous jobs have completed
    Wait-RSJob   $RSJob | Out-Null
    Remove-RSJob $RSJob | Out-Null
#endregion

#region Offline VM configuration
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
        } -OutVariable +RSJob | Out-Null
    }

    Wait-RSJob   $RSJob | Out-Null
    Remove-RSJob $RSJob | Out-Null
#endregion

#region In-guest customization
    # Once merged, start VMs, then continue configuration inside the guest.
    # Previous tasks needed the shutdown/reboot anyway e.g. domain join and ghost NIC removal

    Reset-AzStackVMs -Start -VMs $AllVMs -Wait

    Set-AzureStackHCIVMAdapters
#endregion

    Write-Host '\\\ Completed Environment Setup  ///'
    Write-Host '/// Starting checkpoint creation \\\'

    #Note: Snapshots creation and restoration are labelled by what's done,
    #      e.g. Stage 1 snapshot = all features are installed; stage 3 = cluster is created

    # Create Default and Stage 1 Snapshots
    New-AzureStackHCIStageSnapshot -Stage 0, 1, 3
    Restore-AzureStackHCIStageSnapshot -Stage 0

    $EndTime = Get-Date
    "Start Time: $StartTime"
    "End Time: $EndTime"
}

<#TODO: Cleanup todos!
- Test that labconfig is available and not malformed
- Support using an existing VHD. Make sure it syspreps and adds the unattend file, etc.

- only remove disks if they are greater than 4096 KB
- Only remove NICs if list is different than config file?

- Add tests, at least one machine with the role domain controller
- at least 2 machines with the AzureStackHCI role

- Stage 3 of checkpoints
- support for existing VHD Basedisk
#>