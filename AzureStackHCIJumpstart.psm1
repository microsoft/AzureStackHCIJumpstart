Function Get-AzureStackHCILabConfig {
    # This is the path where VMs will be created for the lab e.g. c:\DataStore\VMs (then \VM01 folder will be added below it)
    $global:VMPath = 'C:\ClusterStorage\Volume01'
    New-Item -Path $VMPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    $LabConfig = @{
        # Will be appended to every VM
        Prefix     = 'AS'

        # Username will not be generated due to an issue with xActiveDirectory
        DomainAdminName   = 'Bruce'
        AdminPassword     = 'd@rkKnight!'

        # The FQDN of the lab domain to be created
        DomainName        = 'gotham.city'

        # DO NOT USE - Has not been updated for multiple server ISOs required with HCI OS and WS OS for DC/WAC
        # This is the filepath to the ISO that will be used to deploy the lab VMs
        #ServerISO   = 'C:\Datastore\19507.1000.191028-1403.rs_prerelease_SERVER_VOL_x64FRE_en-us.iso'

        # This is the filepath to the BaseDisk that will be used to deploy the lab VMs
        BaseVHDX_HCI = 'C:\DataStore\base\20348.30137.amd64fre.fe_release_svc_staging.220526-1750_server_serverAzureStackHCICor_en-us.vhdx'
        BaseVHDX_WS  = 'C:\DataStore\base\20348.30137.amd64fre.fe_release_svc_staging.220526-1750_server_serverdatacenter_en-us_vl.vhdx'

        # This is the name of the internal switch to attach VMs to. This uses DHCP to assign VMs IPs and uses NAT to avoid taking over your network...
        # If the specified switch doesn't exist an Internal switch will be created AzureStackHCILab-Guid.
        #Note: Only /24 is supported right now.
        DHCPscope     = '10.0.0.0'

        SwitchName = 'ASZHCI'
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
                @{ InterfaceDescription = 'Mellanox Connect-X CX6'}
                @{ InterfaceDescription = 'Mellanox Connect-X CX6'}
            )
        }
    }

    # Specify WAC System; does not install WAC, just creates server. You will need to ManageAs in WAC due to known CredSSP Bug
    $LABConfig.VMs += @{
        VMName = 'WAC01'
        MemoryStartupBytes = 4GB

        # Accept folders of MSI's or a specific MSI
<#
        MSIInstaller = @(
            @{ Path = 'c:\datastore\folderA' } ,
            @{ Path = 'c:\datastore\MSIFile1.msi' }
            # @{ Path = 'c:\datastore\MSIFile1.msi'; CustomCommands = '' }
        )

        FileCopy = @(
            @{
                local  = 'c:\datastore\folderA'
                remote = 'c:\PathOnVM\folderA'
            }
            @{
                local  = 'c:\datastore\abc.txt'
                remote = 'c:\xyz\abc.txt'
            }
        )
#>
        #TODO: Add flag to specify the path to the W10 media if not to use Server
        # This should always be WAC
        Role = 'WAC'
    }

    $LABConfig.VMs += @{
        VMName        = 'DC01'
        MemoryStartupBytes = 4GB

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

    if (-not ($labConfig)) { $global:LabConfig = Get-AzureStackHCILabConfig }

    If ($FireAndBrimstone) { Write-Host 'Fire and Brimstone was specified -- This environment will self-destruct in T-5 seconds' ; Start-Sleep -Seconds 5 }

    # Reimporting in case this is run directly
    $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
    Write-Host "Azure Stack HCI Jumpstart module is running from: $here"

    $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
    Import-Module $helperPath -Force

    if (-not ($labConfig)) { $global:LabConfig = Get-AzureStackHCILabConfig }

    $AllVMs = @()
    $AzureStackHCIVMs = @()

    $LabConfig.VMs | ForEach-Object { $AllVMs += "$($LabConfig.Prefix)$($_.VMName)" }
    $LabConfig.VMs.Where{$_.Role -eq 'AzureStackHCI'} | ForEach-Object { $AzureStackHCIVMs += "$($LabConfig.Prefix)$($_.VMName)" }

    If (-not($FireAndBrimstone)) {
        # Removing computer objects from AD (including CNO (LabConfig.Prefix)) if Fire and Brimstone was not specified
        $DomainController = $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' }
        $DCName = "$($LabConfig.Prefix)$($DomainController.VMName)"

        $DC = Get-VM -Name $DCName -ErrorAction SilentlyContinue

        if ($DC) {
            Write-Host "Starting Domain Controller to remove computer accounts"
            Start-VM -Name $DCName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            Wait-ForHeartbeatState -State On -VMs $DC

            #TODO: restore to stage 0 snapshot if available and delete stage 3 snapshot

            #TODO: Troubleshoot "Attempting to perform the InitializeDefaultDrives operation on the 'ActiveDirectory' provider failed."
            #Note: AD Cmdlets don't respect normal param for ErrorAction SilentlyContinue
            $ErrorActionPreference = 'SilentlyContinue'
            Invoke-Command -VMName $DCName -Credential $VMCred -ScriptBlock {
                $using:AzureStackHCIVMs | ForEach-Object {
                    $thisVM = $_
                    Get-ADComputer -identity $thisVM | Remove-ADObject -Recursive -Confirm:$false
                }

                # Default cluster account - Custom cluster accounts won't be removed.
                $thisVM = $($using:LabConfig.Prefix)
                Get-ADComputer -identity $thisVM | Remove-ADObject -Recursive -Confirm:$false
            }

            $ErrorActionPreference = 'Continue'
        }
    }

    # This switch to the VM Object is ugly and should change.
    $AzureStackHCIVMs = Get-VM $AzureStackHCIVMs -ErrorAction SilentlyContinue
    $AllVMs = Get-VM -Name $AllVMs -ErrorAction SilentlyContinue

    Reset-AzStackVMs -Stop -VMs $AllVMs

    If ($AzureStackHCIVMs -ne $null) {
        Write-Host "Destroying HCI VMs"

        Write-Host "`t Checking for and removing snapshots"
        Get-VMSnapshot -VMName $AzureStackHCIVMs.Name -ErrorAction SilentlyContinue | Remove-VMSnapshot -ErrorAction SilentlyContinue

        Write-Host "`t Checking for and removing VMs"
        Remove-VM -Name $AzureStackHCIVMs.Name                 -Force -ErrorAction SilentlyContinue

        Write-Host "`t Cleaning up VM storage"
        Remove-Item -Path $AzureStackHCIVMs.Path -Recurse -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -Path "$VMPath\buildData" -Force -Recurse -ErrorAction SilentlyContinue

    If ($FireAndBrimstone) {
        Write-Host 'Fire and Brimstone mode'
        Write-Host " - Destroying Domain Controller"

        If ($AllVMs -ne $null) {
            Remove-VM -Name $AllVMs.Name                   -Force -ErrorAction SilentlyContinue
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

Function New-AzureStackHCIStageSnapshot {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('0', '1', '2', '3', '4')]
        [Int32[]] $Stage
    )

    #TODO: Need to add a test for each stage to ensure the machines are ready
    $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if (-not ($isAdmin)) { Write-Error 'This must be run as an administrator - Please relaunch with administrative rights' -ErrorAction Stop }
    if (-not ($labConfig)) { $global:LabConfig = Get-AzureStackHCILabConfig }
    if (-not ($here)) {
        $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
        $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
        Import-Module $helperPath -Force
    }

    $global:AllVMs, $global:AzureStackHCIVMs = Get-LabVMs

    Switch ($Stage) {
        0 {
            $AllVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Stage 0 Checkpoints" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    [Console]::WriteLine("Verifying Starting checkpoint exists for: $($thisJobVM.Name)")
                    If (-not (Get-VMSnapshot -VMName $thisJobVM.Name -Name Start -ErrorAction SilentlyContinue)) {
                        [Console]::WriteLine("`tCreating starting checkpoint for: $($thisJobVM.Name)")
                        Checkpoint-VM -Name $thisJobVM.Name -SnapshotName 'Start'
                    }
                    Else { [Console]::WriteLine("Stage 0 (Start) Snapshot already exists for: $($thisJobVM.Name)") }
                } -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null

            # Inserting sleep due to race - Checkpoints report complete before they actually are.
            Start-Sleep -Seconds 5
        }

        1 {
            #TODO: Don't allow stage 1 without taking stage 0
            #[Console]::WriteLine('Applying Start Checkpoint prior to beginning Stage 1')
            #Restore-AzureStackHCIStageSnapshot -Stage 0

            [Console]::WriteLine('Ensuring machines are on')
            Reset-AzStackVMs -Start -Wait -VMs $AllVMs

            $AzureStackHCIVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Stage 1 Checkpoints for HCI VMs" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    [Console]::WriteLine("Checking and/or Installing Stage 1 Features for: $($thisJobVM.Name)")
                    Invoke-Command -VMName $thisJobVM.Name -Credential $using:VMCred -ScriptBlock {
                        Install-WindowsFeature -Name 'Bitlocker', 'Data-Center-Bridging', 'Failover-Clustering', 'FS-Data-Deduplication', 'Hyper-V', 'RSAT-AD-PowerShell' -IncludeManagementTools -Restart
                    }
                }  -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null

            Wait-ForHeartbeatState -State On -VMs $AzureStackHCIVMs

            # This check is due to a timing issue. Some VMs may still be "Applying Computer Settings" which leads to
            # an issue where the stage 1 snapshot is incomplete e.g. it installed failover clustering but the firewall rules aren't added
            [Console]::WriteLine("Ensuring VMs have completed the installation")
            $AzureStackHCIVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Verify Install Complete" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    [Console]::WriteLine("Checking Stage 1 pending features for: $($thisJobVM.Name)")
                    Invoke-Command -VMName $thisJobVM.Name -Credential $using:VMCred -ScriptBlock {
                        #Note: Check for install pending the first time, then loop till its null
                        $InstallPending = Get-WindowsFeature | Where-Object Installstate -eq 'InstallPending'

                        While ($InstallPending -ne $Null) {
                            $InstallPending = Get-WindowsFeature | Where-Object Installstate -eq 'InstallPending'
                            Start-Sleep -Seconds 5
                        }
                    }
                }  -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null

            [Console]::WriteLine("Ensuring VMs are online after installation")
            Wait-ForHeartbeatState -State On -VMs $AzureStackHCIVMs

            $AzureStackHCIVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Stage 1 Checkpoints for HCI VMs" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Disable-VMIntegrationService -VMName $thisJobVMName -Name 'VSS'
                    Enable-VMIntegrationService  -VMName $thisJobVMName -Name 'VSS'

                    [Console]::WriteLine("`t Verifying Stage 1 checkpoint exists for: $($thisJobVM.Name)")
                    If (-not (Get-VMSnapshot -VMName $thisJobVM.Name -Name 'Stage 1 Complete' -ErrorAction SilentlyContinue)) {
                        [Console]::WriteLine("`t `tCreating Stage 1 checkpoint for: $($thisJobVM.Name)")
                        Checkpoint-VM -Name $thisJobVM.Name -SnapshotName 'Stage 1 Complete'
                    }
                    Else { [Console]::WriteLine('Stage 1 Snapshot already exists') }
                } -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null

            # Inserting sleep due to race - Checkpoints report complete before they actually are.
            Start-Sleep -Seconds 5
        }

        2 {
            #TODO: Don't allow stage 1 without taking stage 0
            #[Console]::WriteLine('Applying Start Checkpoint prior to beginning Stage 1')
            #Restore-AzureStackHCIStageSnapshot -Stage 1

            #[Console]::WriteLine('Ensuring machines are on')
            #Reset-AzStackVMs -Start -Wait -VMs $AzureStackHCIVMs

            Remove-Variable IPOffset -ErrorAction SilentlyContinue
            $HostNum = 0
            $AzureStackHCIVMs | ForEach-Object {
                $thisVM = $_

                Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {

                    Remove-VMSwitch -Name * -Force -ErrorAction SilentlyContinue
                    $DataAdapters = Get-NetAdapter | Where-Object Name -like "Ethernet*" | Sort-Object Name

                    $DataAdapters | ForEach-Object {
                        $thisDataAdapter = $_
                        Remove-NetIPAddress -InterfaceAlias $thisDataAdapter.Name -Confirm:$false -ErrorAction SilentlyContinue
                    }

                    Remove-Variable lastOctet, subnet -ErrorAction SilentlyContinue
                    New-VMSwitch -Name 'ComputeSwitch' -AllowManagementOS $false -NetAdapterName ($DataAdapters.Name | Select-Object -First 2) | Out-Null

                    $subnet = 0
                    $lastOctet = $using:HostNum + 1
                    $DataAdapters | Select-Object -Skip 2 | ForEach-Object {
                        $thisDataAdapter = $_

                        $subnet ++

                        #TODO: Move this subnet to the config file, then check that this subnet and the DHCP subnet don't conflict
                        New-NetIPAddress -InterfaceAlias $thisDataAdapter.Name -IPAddress "192.168.$subnet.$lastOctet" | Out-Null
                        Set-NetIPAddress -InterfaceAlias $thisDataAdapter.Name -IPAddress "192.168.$subnet.$lastOctet" -PrefixLength 24 | Out-Null
                    }
                }

                $HostNum ++
            }

            $AzureStackHCIVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Stage 2 Checkpoints for HCI VMs" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Disable-VMIntegrationService -VMName $thisJobVMName -Name 'VSS'
                    Enable-VMIntegrationService  -VMName $thisJobVMName -Name 'VSS'

                    [Console]::WriteLine("`t Verifying Stage 2 checkpoint exists for: $($thisJobVM.Name)")
                    If (-not (Get-VMSnapshot -VMName $thisJobVM.Name -Name 'Stage 2 Complete' -ErrorAction SilentlyContinue)) {
                        [Console]::WriteLine("`t `tCreating Stage 2 checkpoint for: $($thisJobVM.Name)")
                        Checkpoint-VM -Name $thisJobVM.Name -SnapshotName 'Stage 2 Complete'
                    }
                    Else { [Console]::WriteLine('Stage 2 Snapshot already exists') }
                } -OutVariable +RSJob | Out-Null
            }
        }

        3 {
            [Console]::WriteLine('Ensuring machines are on')
            $LabConfig.VMs.Where{$_.Role -eq 'WAC'} | ForEach-Object { $WACVMName += "$($LabConfig.Prefix)$($_.VMName)" }
            Reset-AzStackVMs -Start -Wait -VMs $AllVMs.Where{$_.Name -ne $WACVMName}

            # Clear-ClusterNode needs to be done prior to creating cluster. Issue experienced where each
            # node reports: "The computer 'Name' is joined to a cluster" despite not being joined
            $AzureStackHCIVMs | ForEach-Object {
                $thisVM = $_
                Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock { Clear-ClusterNode -Force }
            }

            $AzureStackHCIVMs | Select-Object -First 1 | ForEach-Object {
                $thisVM = $_

                [Console]::WriteLine("`t Prepping Stage 3 - Clustering")
                [Console]::WriteLine("`t `t Running Test Cluster on: $($thisVM.Name)")
                Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock { Test-Cluster -Node $($Using:AzureStackHCIVMs.Name) -WarningAction SilentlyContinue | Out-Null }

                $DomainController = $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' }
                $DCName = "$($LabConfig.Prefix)$($DomainController.VMName)"

                $ErrorActionPreference = 'SilentlyContinue'
                $CNOExists = Invoke-Command -VMName $DCName -Credential $VMCred -ScriptBlock {
                    #Note: Have to try/catch because remove-adcomputer still errors if account doesn't exist even with erroraction silentlycontinue
                    try { Remove-ADComputer -Identity "$($using:LabConfig.Prefix)" -Confirm:$false }
                    catch { [Console]::WriteLine("`t `t CNO was not found. Continuing with cluster creation)") }
                    finally { $CNO = Get-ADComputer -Identity "$($using:LabConfig.Prefix)" -ErrorAction SilentlyContinue }

                    return $CNO
                }
                $ErrorActionPreference = 'Continue'

                #TODO: Check that the cluster was actually enabled prior to taking snapshot
                if ($CNOExists) {
                    [Console]::WriteLine("`n `t AzStackHCI Computer account was unable to be removed and the Cluster won't be able to be created. Remove Stage 3 snapshots, troubleshoot the removal of the CNO Account and try again")
                }
                Else {
                    Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
                        $thisLabConfig = $using:LabConfig
                        $theseAzureStackHCIVMs = $using:AzureStackHCIVMs

                        $ClusterName = "$($thisLabConfig.Prefix)"
                        New-Cluster -Name $ClusterName -Node $($theseAzureStackHCIVMs.Name) -Force | Out-Null
                    }
                }
            }

            # Need the DC now that there is an AD Object
            $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' -or $_.Role -eq 'AzureStackHCI' } | Foreach-Object {
                $thisVMName = "$($LabConfig.Prefix)$($_.VMName)"

                [Console]::WriteLine("`t Creating Stage 3 checkpoint for: $thisVMName")
                Start-RSJob -Name "Stage 3 Checkpoint for: $($thisVMName)" -ScriptBlock {
                    $thisJobVMName = $using:thisVMName

                    Disable-VMIntegrationService -VMName $thisJobVMName -Name 'VSS'
                    Enable-VMIntegrationService  -VMName $thisJobVMName -Name 'VSS'

                    If (-not (Get-VMSnapshot -VMName $thisJobVMName -Name 'Stage 3 Complete' -ErrorAction SilentlyContinue)) {
                        [Console]::WriteLine("`t `tCreating Stage 3 checkpoint for: $($thisJobVMName)")
                        Checkpoint-VM -Name $thisJobVMName -SnapshotName 'Stage 3 Complete'
                        Start-Sleep -Seconds 5
                    }
                    Else { [Console]::WriteLine('Stage 3 Snapshot already exists') }
                } -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null
        }

        4 {
            [Console]::WriteLine('Ensuring machines are on')
            Reset-AzStackVMs -Start -Wait -VMs $AllVMs

            [Console]::WriteLine("`t Prepping Stage 4 - S2D")
            $AzureStackHCIVMs | Select-Object -First 1 | ForEach-Object {
                $thisVM = $_

                [Console]::WriteLine("`t `t Cleaning disks and enabling S2D")
                Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
                    $thisLabConfig = $using:LabConfig

                    Start-ClusterResource -Name 'Cluster Name' | Out-Null

                    (Get-Cluster -Name $($thisLabConfig.Prefix)).BlockCacheSize = 2048
                    Update-StorageProviderCache

                    Get-Disk | Where-Object Number -ne $null | Where-Object IsBoot -ne $true | Where-Object IsSystem -ne $true | Where-Object PartitionStyle -ne RAW | ForEach-Object {
                        $_ | Clear-Disk -RemoveData -Confirm:$false
                    }

                    Enable-ClusterStorageSpacesDirect -Confirm:$false | Out-Null
                }
            }

            #TODO: Check that S2D was actually enabled prior to taking snapshot
            $LabConfig.VMs.Where{ $_.Role -eq 'AzureStackHCI' } | Foreach-Object {
                $thisVMName = "$($LabConfig.Prefix)$($_.VMName)"

                [Console]::WriteLine("`t Creating Stage 4 checkpoint for: $thisVMName")
                Start-RSJob -Name "Stage 4 Checkpoint for: $($thisVMName)" -ScriptBlock {
                    $thisJobVMName = $using:thisVMName

                    Disable-VMIntegrationService -VMName $thisJobVMName -Name 'VSS'
                    Enable-VMIntegrationService  -VMName $thisJobVMName -Name 'VSS'

                    If (-not (Get-VMSnapshot -VMName $thisJobVMName -Name 'Stage 4 Complete' -ErrorAction SilentlyContinue)) {
                        [Console]::WriteLine("`t `tCreating Stage 4 checkpoint for: $($thisJobVMName)")
                        Checkpoint-VM -Name $thisJobVMName -SnapshotName 'Stage 4 Complete'
                        Start-Sleep -Seconds 5
                    }
                    Else { [Console]::WriteLine('Stage 4 Snapshot already exists') }
                } -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null
        }
    }
}

Function Restore-AzureStackHCIStageSnapshot {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('0', '1', '2', '3', '4')]
        [Int32] $Stage
    )

    $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if (-not ($isAdmin)) { Write-Error 'This must be run as an administrator - Please relaunch with administrative rights' -ErrorAction Stop }
    if (-not ($labConfig)) { $global:LabConfig = Get-AzureStackHCILabConfig }
    if (-not ($here)) {
        $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
        $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
        Import-Module $helperPath -Force
    }

    $global:AllVMs, $global:AzureStackHCIVMs = Get-LabVMs

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
        }

        1 {
            #TODO: Where -ne to domain controller
            $AllVMs | ForEach-Object {
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
        }

        2 {
            $AllVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Restoring Stage 2" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Restore-VMSnapshot -Name 'Stage 2 Complete' -VMName $thisJobVM.Name -Confirm:$false
                } -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null
        }

        3 {
            #TODO: Where not WAC
            $AllVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Restoring Stage 3" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Restore-VMSnapshot -Name 'Stage 3 Complete' -VMName $thisJobVM.Name -Confirm:$false
                } -OutVariable +RSJob | Out-Null
            }
            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null

            Write-Host "Starting "
            Reset-AzStackVMs -Start -Wait -VMs $AllVMs

            $AzureStackHCIVMs | Select-Object -First 1 | ForEach-Object {
                $thisVM = $_

                Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
                    Start-ClusterResource -Name 'Cluster Name' | Out-Null
                }
            }
        }

        4 {
            $AllVMs | ForEach-Object {
                $thisVM = $_
                Start-RSJob -Name "$($thisVM.Name)-Restoring Stage 4" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Restore-VMSnapshot -Name 'Stage 4 Complete' -VMName $thisJobVM.Name -Confirm:$false
                } -OutVariable +RSJob | Out-Null
            }

            Wait-RSJob   $RSJob | Out-Null
            Remove-RSJob $RSJob | Out-Null
        }
    }
}

Function Remove-AzureStackHCIStageSnapshot {
    param (
        [Parameter(Mandatory=$false)]
        [ValidateSet('0', '1', '2', '3', '4')]
        [Int32] $Stage
    )

    $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if (-not ($isAdmin)) { Write-Error 'This must be run as an administrator - Please relaunch with administrative rights' -ErrorAction Stop }
    if (-not ($labConfig)) { $global:LabConfig = Get-AzureStackHCILabConfig }
    if (-not ($here)) {
        $here = Split-Path -Parent (Get-Module -Name AzureStackHCIJumpstart).Path
        $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
        Import-Module $helperPath -Force
    }

    $global:AllVMs, $global:AzureStackHCIVMs = Get-LabVMs

    Switch ($Stage) {
        0 {
            $AllVMs | ForEach-Object {
                $thisVM = $_

                Start-RSJob -Name "$($thisVM.Name)-RemoveStage1Snapshots" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Get-VMSnapshot -VMName $thisJobVM.Name | Where-Object Name -eq 'Start' | Remove-VMSnapshot -IncludeAllChildSnapshots
                } -OutVariable +RSJob | Out-Null
            }
        }

        1 {
            $AllVMs | ForEach-Object {
                $thisVM = $_

                Start-RSJob -Name "$($thisVM.Name)-RemoveStage1Snapshots" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Get-VMSnapshot -VMName $thisJobVM.Name | Where-Object Name -like 'Stage 1*' | Remove-VMSnapshot -IncludeAllChildSnapshots
                } -OutVariable +RSJob | Out-Null
            }
        }

        2 {
            $AllVMs | ForEach-Object {
                $thisVM = $_

                Start-RSJob -Name "$($thisVM.Name)-RemoveStage3Snapshots" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Get-VMSnapshot -VMName $thisJobVM.Name | Where-Object Name -like 'Stage 2*' | Remove-VMSnapshot -IncludeAllChildSnapshots
                } -OutVariable +RSJob | Out-Null
            }
        }

        3 {
            $AllVMs | ForEach-Object {
                $thisVM = $_

                Start-RSJob -Name "$($thisVM.Name)-RemoveStage3Snapshots" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Get-VMSnapshot -VMName $thisJobVM.Name | Where-Object Name -like 'Stage 3*' | Remove-VMSnapshot -IncludeAllChildSnapshots
                } -OutVariable +RSJob | Out-Null
            }
        }

        4 {
            $AllVMs | ForEach-Object {
                $thisVM = $_

                Start-RSJob -Name "$($thisVM.Name)-RemoveStage4Snapshots" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Get-VMSnapshot -VMName $thisJobVM.Name | Where-Object Name -like 'Stage 4*' | Remove-VMSnapshot -IncludeAllChildSnapshots
                } -OutVariable +RSJob | Out-Null
            }
        }

        default {
            Write-Host 'No snapshot stage was specified. Removing all snapshots'
            Start-Sleep -Seconds 3

            $AllVMs | ForEach-Object {
                $thisVM = $_

                Start-RSJob -Name "$($thisVM.Name)-RemoveAllSnapshots" -ScriptBlock {
                    $thisJobVM = $using:thisVM

                    Get-VMSnapshot -VMName $thisJobVM.Name | Where-Object ParentSnapshotName -eq $null | Remove-VMSnapshot -IncludeAllChildSnapshots
                } -OutVariable +RSJob | Out-Null
            }
        }
    }

    if ($ranOOB) {
        $EndTime = Get-Date
        "Start Time: $StartTime"
        "End Time: $EndTime"
    }

    Wait-RSJob   $RSJob | Out-Null
    Remove-RSJob $RSJob | Out-Null
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

    # If there were prior RSJobs, remove them
    Get-RSJob | Remove-RSJob

    Get-ChildItem "$here\helpers\ModulesTillPublishedonGallery" -Exclude PoshRSJob | foreach-Object {
        $thisModule = $_
        $path = $_.FullName
        $destPath = "C:\Program Files\WindowsPowerShell\Modules\"

        Start-RSJob -Name "$($thisModule.Name)-Modules" -ScriptBlock {
            Copy-Item -Path $using:path -Recurse -Destination "$($using:destPath)\$($thisModule.Name)" -Container -ErrorAction SilentlyContinue | Out-Null
        } -OutVariable +RSJob | Out-Null
    }

    Wait-RSJob   $RSJob | Out-Null
    Remove-RSJob $RSJob | Out-Null

    Get-ChildItem "$here\helpers\ModulesTillPublishedonGallery" -Exclude PoshRSJob | foreach-Object {
        Import-Module -Name $_ -Force -Global -ErrorAction SilentlyContinue
    }
#endregion

    $helperPath = Join-Path -Path $here -ChildPath 'helpers\helpers.psm1'
    Import-Module $helperPath -Force

    $global:LabConfig = Get-AzureStackHCILabConfig

    #TODO: If VMs already exist, return them to stage0 snapshot and delete the snapshots before continuing

    $timer = Get-Date
    "Beginning Host Approval Time: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append

    # Check that the host is ready with approve host state
    Approve-AzureStackHCILabState -Test Host

    $timer = Get-Date
    "Completed Host Approval Time: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append
#region BaseDisk and VM Create

<#
    # Hydrate base disk - this is long and painful...
    # Note: This does not currently work for additional BaseDisks added to specific VMs
    # Since Azure Stack HCI removed AD and the UI, you now need two base disks
    if ($LabConfig.ServerISO) {
        New-BaseDisk

        $timer = Get-Date
        "Completed base disk creation: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append
    }
#>

    # Update BaseDisk with buildData
    if ('AzureStackHCI'     -in $LabConfig.VMs.Role) { Initialize-HCIBaseDisk }
    if ('Domain Controller' -in $LabConfig.VMs.Role -or 'WAC' -in $LabConfig.VMs.Role) { Initialize-WSBaseDisk }

    $timer = Get-Date
    "Completed base disk initialization: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append

    # Create Virtual Machines
    Add-LabVirtualMachines
    $global:AllVMs, $global:AzureStackHCIVMs = Get-LabVMs

    $timer = Get-Date
    "Completed VM Creation: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append
#endregion

#region VM Startup
    # Start DC only; want this to startup as quickly as possible to begin creating the long running domain
    Write-Host "Starting DC VM" | Out-File $logfile.fullname -Append

    $DCName = $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' }
    $DC     = Get-VM -VMName "$($LabConfig.Prefix)$($DCName.VMName)" -ErrorAction SilentlyContinue
    Reset-AzStackVMs -Start -VMs $DC
    Wait-ForHeartbeatState -State On -VMs $DC -IgnoreLoopCount #Note: Added for slow systems to give more time to startup

    $timer = Get-Date
    "Completed Domain Controller VM initialization: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append

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

            $metaConfig = Test-Path "$using:VMPath\buildData\config\localhost.meta.mof" -ErrorAction SilentlyContinue
            $DCConfig   = Test-Path "$using:VMPath\buildData\config\localhost.mof" -ErrorAction SilentlyContinue
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
        [Console]::WriteLine("`t BuildDataExists: $BuildDataExists")
        if ($RebootIsNeeded) { Reset-AzStackVMs -VMs $DC -Restart -Wait }

        if ($BuildDataExists -eq $false -or $RebootIsNeeded -eq $true) { Start-Sleep -Seconds 10 }
    } Until (($BuildDataExists -eq $true) -and ($RebootIsNeeded -eq $false))

    Remove-Variable RebootIsNeeded

    $timer = Get-Date
    "Completed Domain Controller rename, reboot, scheduled tasks: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append
#endregion

#region Domain Creation and VM online customization
    $timer = Get-Date
    "Initializing domain creation: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append
    # This runs asynchronously as nothing depends on this being complete at this point
    Write-Host "`t Configuring Domain Controller takes a while. Please be patient"
    Assert-LabDomain

    $timer = Get-Date
    "Initializing non-Domain controller VMs: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append

    #Note: We've got time on our side here...Domain is being configured and reparenting is occuring which means we can get other stuff done while waiting.
    # Now start all other VMs - Don't wait for completion, but stagger startup for hosts with slow disks if the OSD is the default size (4096KB) indicating it's not started before.
    Write-Host "Starting All VMs - Will stagger if this is first startup"

    $VMCounter = 1
    $AllVMs.Where{ $_.Role -ne 'Domain Controller' } | Foreach-Object {
        $thisVM = $_
        $VMCounter ++

        <# Get OSD VHD file length. If greater than specified size (default size is 4MB) then machine has started up previously and we can start the next VM
            If this is the first startup, this delay will let each individual VM startup faster since there will likely be less disk churn
            In testing this allowed startup to occur much more rapidly and on low memory machines, allows dynamic memory to reclaim memory #>

        Write-host "`t Starting VM $($thisVM.Name)"
        Reset-AzStackVMs -Start -VMs $thisVM

        # If there are only 2 VMs left to start, just keep going...no more delays, get on with it.
        If (($VMCounter - 2) -le $AllVMs.Count) {
            $thisVMOSDLength = 4MB # Initializing - Do not remove

            $VHDXExtension = (Get-ChildItem -Path ($thisVM | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0).Path).Extension
            if ($VHDXExtension -ne '.avhdx') {
                While ($thisVMOSDLength -le 350MB) {
                    $thisVMOSDLength = (Get-ChildItem -Path ($thisVM | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0).Path).Length
                    Start-Sleep -Seconds 3
                }
            }
        }
    }

    $timer = Get-Date
    "Completed non-domain controller VMs initialization: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append

    # Begin long-running reparent task - runs async
    $AllVMs | ForEach-Object {
        $thisVM = $_

        Start-RSJob -Name "$($thisVM.Name)-Reparent" -ScriptBlock {
            $thisJobVM = $using:thisVM

            $VHDXToConvert = $thisJobVM | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0
            $ParentPath   = Split-Path -Path $VHDXToConvert.Path -Parent
            $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath

            [Console]::WriteLine("Copying VHDX base disk for reparenting on $($thisJobVM.Name)")

            $BaseLeaf = Split-Path $BaseDiskPath -Leaf
            $NewBasePath = Join-Path -Path $ParentPath -ChildPath $BaseLeaf
            Copy-Item -Path $BaseDiskPath -Destination $NewBasePath -InformationAction SilentlyContinue

            [Console]::WriteLine("`t Reparenting $($thisJobVM.Name) OSD to $NewBasePath")
            $VHDXToConvert | Set-VHD -ParentPath $NewBasePath -IgnoreIdMismatch
        } -OutVariable +RSJob | Out-Null
    }

    $timer = Get-Date
    "Completed VHDX Reparenting: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append

    # Cleanup VM hardware (S2D disks and NICs) and recreate (later) in case this is not the first run
    [Console]::WriteLine("Cleaning up then re-adding VM hardware in case this is not the first run")
    Remove-AzureStackHCIVMHardware

    # Recreate NICs - Disks can't be done yet because adding new SCSI controllers require them to be offline
    New-AzureStackHCIVMAdapters

    #TODO: This needs to wait as the tasks are run through RSJobs
    $timer = Get-Date
    "Completed VMHardware removal and adapter reinitialization: $($timer.ToString("hh:mm:ss.fff"))" | Out-File $logfile.fullname -Append

    # Cleanup Ghosts; System must be on but will require a full shutdown (not restart) to complete the removal so don't rename NICs yet.
    Wait-ForHeartbeatState -State On -VMs $AllVMs

    Write-Host "`t Registering Startup Tasks"
    Register-AzureStackHCIStartupTasks -VMs $AllVMs.Where{$_.Name -ne $DC.Name}

    $LabConfig.VMs.Where{ $_.Role -ne 'Domain Controller' } | Foreach-Object {
        $thisVMName = "$($LabConfig.Prefix)$($_.VMName)"

        Write-Host "`t Removing any Ghost NICs in $($thisVMName) and enabling firewall rules (SMB-in and Echo-in)"
        Invoke-Command -VMName $thisVMName -Credential $localCred -ScriptBlock {
            $ghosts = Get-PnpDevice -class net | Where-Object Status -eq Unknown | Select-Object FriendlyName,InstanceId

            ForEach ($ghost in $ghosts) {
                $RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($ghost.InstanceId)"
                Get-Item $RemoveKey | Select-Object -ExpandProperty Property | Foreach-Object { Remove-ItemProperty -Path $RemoveKey -Name $_ }
            }

            Get-NetFirewallRule -DisplayName "*File and Printer Sharing (Echo Request*In)" | Enable-NetFirewallRule
            Get-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" | Enable-NetFirewallRule
        }
    }

    # Make sure all previous jobs have completed
    Wait-RSJob   $RSJob | Out-Null
    Remove-RSJob $RSJob | Out-Null

    # DC has already been renamed
    $LabConfig.VMs.Where{ $_.Role -ne 'Domain Controller' } | Foreach-Object {
        $thisSystem = "$($LabConfig.Prefix)$($_.VMName)"

        $RebootIsNeeded = Invoke-Command -VMName $thisSystem -Credential $localCred -ScriptBlock {
            if ($env:COMPUTERNAME -ne $using:thisSystem) {
                Rename-Computer -NewName $($using:thisSystem) -Force -WarningAction SilentlyContinue
                return $true
            }
            Else { return $false }
        }

        if ($RebootIsNeeded) {
            [Console]::WriteLine("Rebooting $($thisSystem) to complete hostname change")
            Reset-AzStackVMs -Restart -Wait -VMs (Get-VM $thisSystem)
        }
    }

    Wait-ForAzureStackHCIDomain

    # Create environment Domain Admin
    Invoke-Command -VMName $DC.Name -Credential $localCred -ScriptBlock {
        $thisPass = ConvertTo-SecureString $($using:LabConfig.AdminPassword) -AsPlainText -Force
        New-ADUser -Name $($using:LabConfig.DomainAdminName) -Accountpassword $thisPass -Enabled $true -PasswordNeverExpires $true
        Add-ADGroupMember -Identity 'Domain Admins' -Members $($using:LabConfig.DomainAdminName)
    }

    $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' } | Foreach-Object {
        $thisSystem = "$($LabConfig.Prefix)$($_.VMName)"

        Write-Host 'Configuring DHCPs DNS Update Credentials and removing old computer accounts if they exist'

        $ErrorActionPreference = 'SilentlyContinue'
        Invoke-Command -VMName $thisSystem -Credential $VMCred -ScriptBlock {
            $thisLabConfig = $using:LabConfig

            Set-DnsServerPrimaryZone -Name "$($thisLabConfig.DomainName)" -DynamicUpdate "NonsecureAndSecure"

            #Note: Using the $using:VMCred does not work here. Need to create the credential on the remote machine.
            $pass   = ConvertTo-SecureString $($thisLabConfig.AdminPassword) -AsPlainText -Force
            $VMCred = New-Object System.Management.Automation.PSCredential ("$($thisLabConfig.DomainNetbiosName)\$($thisLabConfig.DomainAdminName)", $pass)

            Set-DhcpServerDnsCredential -ComputerName AzStackHCIDC01 -Credential $VMCred

            $thisLabConfig.VMs.Where{ $_.Role -ne 'Domain Controller'} | ForEach-Object {
                $VerbosePreference = 'Continue'
                $thisVM = "$($thisLabConfig.Prefix)$($_.VMName)"

                # This will be blank if the system is not already renamed - try 2x to see if the machine is online
                $Counter = 1
                While ($Counter -ne 2 -and $thisVMComputerSystem -eq $null) {
                    $thisVMComputerSystem = Get-CimInstance -CimSession $thisVM -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue -Verbose:$false
                    if ($thisVMComputerSystem -eq $null) { $Counter ++ }
                }

                if (-not ($thisVMComputerSystem)) {
                    Write-Verbose "Could not verify if $($thisVM) was alive. If a computer account exists in Active Directory with this name, it will be removed."
                    $VerbosePreference = 'SilentlyContinue'
                }

                # If the machine is part of the domain and named properly, leave the account alone
                # If the machine is not part of the domain, remove any existing accounts that match the name as this will prevent domain join: the account already exists
                if ($thisVMComputerSystem.PartOfDomain -ne $true) {
                    Get-ADObject -Filter {Name -eq $thisVM} | Remove-ADObject -Recursive -Confirm:$false
                }

                Remove-Variable Counter -ErrorAction SilentlyContinue
            }

            $ClusterNameIsOnline = Test-NetConnection $($thisLabConfig.Prefix) -InformationLevel Quiet -WarningAction SilentlyContinue

            if ($ClusterNameIsOnline -eq $false) {
                $CNOName = $($thisLabConfig.Prefix)
                Get-ADObject -Filter {Name -eq $CNOName} | Remove-ADObject -Recursive -Confirm:$false
            }
        }

        $ErrorActionPreference = 'Continue'
    }

    # Join lab VMs to domain
    $LabConfig.VMs.Where{ $_.Role -ne 'Domain Controller' } | Foreach-Object {
        $thisSystem = "$($LabConfig.Prefix)$($_.VMName)"
        Write-Host "Joining $thisSystem to domain"

        Invoke-Command -VMName $thisSystem -Credential $localCred -ScriptBlock {
            if (-not (Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
                # Make sure you get an IP now that DHCP has been configured
                ipconfig /release | Out-Null
                ipconfig /renew   | Out-Null

                # Join computer to domain - Proper name must already be set
                $thisDomain = $($using:LabConfig.DomainNetbiosName)
                Add-Computer -DomainName $thisDomain -LocalCredential $Using:localCred -Credential $using:VMCred -Force -WarningAction SilentlyContinue
            }
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

    # Finish the previous job (adding disks). This occasionally interferes with the merge and its relatively quick.
    Wait-RSJob   $RSJob | Out-Null
    Remove-RSJob $RSJob | Out-Null

    # Prep for Merge
    $AllVMs | ForEach-Object {
        $thisVM = $_

        if ($thisVM.Name -in $AzureStackHCIVMs.Name) { $BaseDiskACL = Get-ACL $HCIVHDPath }
        else { $BaseDiskACL = Get-ACL $WSVHDPath }

        $OSDDisk = Get-VHD "$($thisVM.Path)\Virtual Hard Disks\OSD.VHDX" -ErrorAction SilentlyContinue

        If ($OSDDisk) {
            #TODO: Readd disk at the beginning of the initialize in case this is restarted after remove vmharddisk occurs. Look for either OSD or merged disk
            Remove-VMHardDiskDrive -VMName $thisVM.Name -ControllerNumber 0 -ControllerLocation 0 -ControllerType SCSI -ErrorAction SilentlyContinue
            $BaseDiskPath = $OSDDisk.ParentPath

            Set-ACL  -Path $BaseDiskPath -AclObject $BaseDiskACL
            Set-ItemProperty -Path $BaseDiskPath -Name IsReadOnly -Value $false
        }

        Remove-Variable BaseDiskACL -ErrorAction SilentlyContinue
    }

    # Begin Merge
    $AllVMs | ForEach-Object {
        $thisVM = $_
        $OSDDisk = Get-VHD "$($thisVM.Path)\Virtual Hard Disks\OSD.VHDX" -ErrorAction SilentlyContinue

        If ($OSDDisk) {
            [Console]::WriteLine("`t Beginning VHDX Merge for $($thisVM.Name)")
            $BaseDiskPath = $OSDDisk.ParentPath
            Merge-VHD -Path $OSDDisk.Path -DestinationPath $BaseDiskPath -Force
        }
        Else { [Console]::WriteLine("`t $($thisVM.Name) VHDX has already been merged - backslash ignore") }
    }

    $AllVMs | ForEach-Object {
        $thisVM = $_

        if ($thisVM.Name -in $AzureStackHCIVMs.Name) {
            $MergedBaseDisk = "$($thisVM.Path)\Virtual Hard Disks\$($HCIVHDPath.Split('\') | Select-Object -Last 1)"
        }
        else {
            $MergedBaseDisk = "$($thisVM.Path)\Virtual Hard Disks\$($WSVHDPath.Split('\') | Select-Object -Last 1)"
        }

        $OSD = Add-VMHardDiskDrive -VM $thisVM -Path $MergedBaseDisk -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -Passthru -ErrorAction SilentlyContinue
        Set-VMFirmware  -VMName $thisVM.Name -BootOrder $OSD

        Remove-Variable MergedBaseDisk -ErrorAction SilentlyContinue
    }
#endregion

    Reset-AzStackVMs -Start -VMs $AllVMs -Wait

    # This must be done after the ghost NICs have been removed and a full shutdown has occurred. Since merge is our only full shutdown, this section must stay after the merge
    Set-AzureStackHCIVMAdapters

    Write-Host '\\\ Completed Environment Setup  ///'
    Write-Host '/// Starting checkpoint creation \\\'

    $EndTime = Get-Date
    "Start Time: $StartTime"
    "End Time: $EndTime"
}

<#TODO: Cleanup todos!
- Test that labconfig is available and not malformed
- Only remove NICs if list is different than config file?

- Once Complete, test that VMs have correct names

- Enable MAC Spoofing on the HV Ethernet vmNICs
- Enable enhanced session mode on HV VMhosts
#>