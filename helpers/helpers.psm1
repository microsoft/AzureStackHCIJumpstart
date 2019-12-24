# These functions are not exported
Function Get-LabConfig {
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
        ServerISOFolder   = 'C:\Datastore\19507.1000.191028-1403.rs_prerelease_SERVER_VOL_x64FRE_en-us.iso'

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

            # This should always be AzureStackHCI
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
        VMName        = 'WAC01'

        # This should always be WAC
        Role          = 'WAC'
        MemoryStartupBytes = 4GB
    }

    $LABConfig.VMs += @{
        VMName        = 'DC01'

        # This should always be Domain Controller
        Role          = 'Domain Controller'
        MemoryStartupBytes = 2GB
    }

    # No touchie! Required but no mods needed - Prep local and domain creds
    $LabConfig.DomainNetbiosName = ($LabConfig.DomainName.Split('.')[0])
    $global:pass   = ConvertTo-SecureString $($LabConfig.AdminPassword) -AsPlainText -Force
    $global:VMCred = New-Object System.Management.Automation.PSCredential ("$($LabConfig.DomainName)\$($LabConfig.DomainAdminName)", $pass)
    $global:localCred = New-Object System.Management.Automation.PSCredential ('.\Administrator', $pass)

    $LabConfig
}

#region Used for VM/Lab configuration

#TODO: Update with rsJob
function Wait-ForHeartbeatState {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('On', 'Off')]
        [string] $State ,

        [Switch] $IgnoreLoopCount ,

        [Microsoft.HyperV.PowerShell.VirtualMachine[]] $VMs
    )

    Remove-Variable TimesThroughLoop -ErrorAction SilentlyContinue

    Switch ($State) {
        'On' {
            $VMs | ForEach-Object {
                While ((Get-VMIntegrationService -VMName $_.Name -Name Heartbeat).PrimaryStatusDescription -ne 'Ok') {
                    [Console]::WriteLine("`t Waiting on Heartbeat for: $($_.Name)")
                    [Console]::WriteLine("`t `t Getting sleepy...")
                    Start-Sleep -Seconds 5

                    if (-not ($IgnoreLoopCount)) { $TimesThroughLoop ++ }

                    # Give machines 1 minute to startup if $IgnoreLoopCount -eq $false;
                    if ($TimesThroughLoop -eq 12) {
                        [Console]::WriteLine("`t `t $($_.Name) may be in broken state. Trying to recover by restarting")
                        [Console]::WriteLine("`t `t `t If this continually occurs, this could either indicate an issue with the VM or its taking a long time to start the system")
                        [Console]::WriteLine("`t `t `t - Consider lengthening this timeout (in the helpers file) if the latter")
                        Stop-VM -VMName $_.Name -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 3
                        Start-VM -VMName $_.Name -ErrorAction SilentlyContinue

                        $TimesThroughLoop = 0
                    }
                }

                [Console]::WriteLine("`t Ensuring PowerShell Direct is ready for: $($_.Name)")

                do {
                    [Console]::WriteLine("`t `t Checking PowerShell Direct on $($_.Name)...Getting sleepy again")
                    $Availability = New-PSSession -VMName $($_.Name) -Credential $localCred -ErrorAction SilentlyContinue

                    Start-Sleep -Seconds 5
                } While ($Availability.State -ne 'Opened')

                Remove-PSSession $Availability
            }
        }

        'Off' {
            $VMs | ForEach-Object {
                While ((Get-VMIntegrationService -VMName $_.Name -Name Heartbeat).PrimaryStatusDescription -ne $null) {
                    Write-Host "`t Shutting down: $($_.Name)"
                    Start-Sleep -Seconds 3
                }
            }
        }
    }
}

#TODO: Update with rsJob
Function Reset-AzStackVMs {
    param (
        [Switch] $Start    ,

        [Switch] $Restart  ,

        [Switch] $Shutdown ,

        [Switch] $Stop     ,

        [Switch] $Wait     ,

        [Microsoft.HyperV.PowerShell.VirtualMachine[]] $VMs
    )

    If ($Start) {
        $VMs | ForEach-Object { Start-VM -VMName $_.Name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }

        If ($Wait) { Wait-ForHeartbeatState -State On -VMs $VMs }
    }

    If ($Restart)  {
        $VMs | ForEach-Object { Restart-VM -VMName $_.Name -Force -Wait -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }

        If ($Wait) { Wait-ForHeartbeatState -State On -VMs $VMs }
    }

    If ($Shutdown) {
        $VMs | ForEach-Object { Stop-VM -VMName $_.Name -WarningAction SilentlyContinue  }
        If ($Wait) { Wait-ForHeartbeatState -State Off -VMs $VMs }
    }

    If ($Stop) {
        $VMs | ForEach-Object { Stop-VM -VMName $_.Name -TurnOff -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }
        If ($Wait) { Wait-ForHeartbeatState -State Off -VMs $VMs }
    }
}
#endregion

#region Used for VM/Lab creation
# Create new base disk
Function New-BaseDisk {
    Write-Host "`t Mounting ISO for Hydration"
    $MountedISO     = Mount-DiskImage -ImagePath $LabConfig.ServerISOFolder -PassThru -InformationAction SilentlyContinue
    $ISODriveLetter = "$((Get-Volume -DiskImage $MountedISO -InformationAction SilentlyContinue).DriveLetter):"
    $BuildNumber    = (Get-ItemProperty -Path (Join-Path -Path $ISODriveLetter -ChildPath "setup.exe") -InformationAction SilentlyContinue).VersionInfo.FileBuildPart
    $WindowsImage   = Get-WindowsImage -ImagePath (Join-Path -Path $ISODriveLetter -ChildPath "sources\install.wim") -InformationAction SilentlyContinue
    $Edition = ($WindowsImage | Where-Object ImageName -like *Server*2019*Datacenter*Desktop*).ImageName
    $vhdname = "BaseDisk_$BuildNumber.vhdx"
    $global:VHDPath = "$VMPath\$vhdname"

    Write-Host "`t The ISO provided contains build number: $BuildNumber"

    if (-not(Test-Path $VHDPath)) {
        Write-Host "`t Hydrating VHDX...Please be patient"

        Convert-WindowsImage -SourcePath "$ISODriveLetter\sources\install.wim" -Edition $Edition -VHDPath $VHDPath -SizeBytes 100GB -VHDFormat VHDX -DiskLayout UEFI | Out-Null
    }

    Write-Host "`t Dismounting ISO Image"
    Dismount-DiskImage -ImagePath $LabConfig.ServerISOFolder -InformationAction SilentlyContinue | Out-Null
}

#Create Unattend for VHD
Function New-UnattendFileForVHD {
    param (
        [parameter(Mandatory=$true)]
        [string]
        $AdminPassword,

        [parameter(Mandatory=$true)]
        [string]
        $Path,

        [parameter(Mandatory=$true)]
        [string]
        $TimeZone
    )

    if ( Test-Path "$Path\Unattend.xml" ) { Remove-Item "$Path\Unattend.xml" -InformationAction SilentlyContinue }

    New-Item "$Path\Unattend.xml" -type File -Force -OutVariable unattendFile | Out-Null
    $fileContent =  @"
    <?xml version="1.0" encoding="utf-8"?>
    <unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <settings pass="offlineServicing">
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            </component>
        </settings>
        <settings pass="oobeSystem">
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
                <AutoLogon>
                    <Password>
                        <Value>$($LabConfig.AdminPassword)</Value>
                        <PlainText>true</PlainText>
                    </Password>
                    <LogonCount>1</LogonCount>
                    <Username>Administrator</Username>
                    <Enabled>true</Enabled>
                </AutoLogon>
                <FirstLogonCommands>
                    <SynchronousCommand wcm:action="add">
                        <CommandLine>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -ExecutionPolicy bypass -File C:\FirstLogon.ps1</CommandLine>
                        <Order>1</Order>
                        <RequiresUserInput>false</RequiresUserInput>
                    </SynchronousCommand>
                </FirstLogonCommands>
                <UserAccounts>
                    <AdministratorPassword>
                        <Value>$($LabConfig.AdminPassword)</Value>
                        <PlainText>true</PlainText>
                    </AdministratorPassword>
                </UserAccounts>
                <OOBE>
                    <HideEULAPage>true</HideEULAPage>
                    <SkipMachineOOBE>true</SkipMachineOOBE>
                    <SkipUserOOBE>true</SkipUserOOBE>
                </OOBE>
                <TimeZone>$TimeZone</TimeZone>
            </component>
        </settings>
        <settings pass="specialize">
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
                <ComputerName>*</ComputerName>
                <RegisteredOwner>$($LabConfig.DomainAdminName)</RegisteredOwner>
                <RegisteredOrganization>$($LabConfig.DomainNetbiosName)</RegisteredOrganization>
            </component>
        </settings>
    </unattend>

"@

    Set-Content -path $unattendFile -value $fileContent

    #return the file object
    Return $unattendFile
}

#Customize Base Disk
Function Initialize-BaseDisk {
    # Create Unattend File; remove old unattend
    $TimeZone  = (Get-TimeZone).id
    Remove-Item -Path "$VMPath\buildData\Unattend.xml" -Force -ErrorAction SilentlyContinue
    New-UnattendFileForVHD -TimeZone $TimeZone -AdminPassword $LabConfig.AdminPassword -Path "$VMPath\buildData"

    #Apply Unattend to VM
    Write-Host "`t Applying Unattend and copying DSC Modules"
    $unattendfile = "$VMPath\buildData\Unattend.xml"

    If ( Test-Path $VHDPath ) {
        Dismount-DiskImage -ImagePath $VHDPath -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
        $MountedDisk = Mount-DiskImage    -ImagePath $VHDPath -StorageType VHDX -ErrorAction SilentlyContinue

        If ( $MountedDisk ) {
            $DriveLetter = $(Get-DiskImage -ImagePath $VHDPath | Get-Disk | Get-Partition | Get-Volume).DriveLetter
            $MountPath = "$($DriveLetter):" -replace ' '

            If ( Test-Path "$MountPath\Windows\Panther\unattend.xml" ) {
                Write-Host "`t Unattend file exists..."
            }
            Else {
                Write-Host "`t Unattend file does not exist...Updating..."

                New-Item -Path "$MountPath\Windows\Panther" -ItemType Directory -Force | Out-Null
                Use-WindowsUnattend -Path $MountPath -UnattendPath $unattendfile -InformationAction SilentlyContinue

                'xActiveDirectory', 'xDNSServer', 'NetworkingDSC', 'xDHCPServer', 'xPSDesiredStateConfiguration' | foreach-Object {
                    $thisModule = $_

                    Start-RSJob -Name "$thisModule-Modules" -ScriptBlock {
                        Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\$($using:thisModule)" -Destination "$($using:MountPath)\Program Files\WindowsPowerShell\Modules\" -Recurse -Force
                    } | Out-Null
                }

                Get-RSJob | Wait-RSJob
                Get-RSJob | Remove-RSJob

                Copy-Item -Path $unattendfile -Destination "$MountPath\Windows\Panther\unattend.xml" -Force
            }

            Copy-Item -Path "$here\helpers\FirstLogon.ps1" -Destination "$MountPath\FirstLogon.ps1" -Force -ErrorAction SilentlyContinue
        }
        Else { Write-Host "`t $VHDPath could not be mounted but was found (likely in use)" }
    }
    Else { Write-Host "$VHDPath was not found - Can't hydrate the basedisk" }

    Dismount-DiskImage -ImagePath $VHDPath -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
    Set-ItemProperty -Path $VHDPath -Name IsReadOnly -Value $true

    # Stuff needed for DCHydration
    $DN = @()
    $LabConfig.DomainName.Split(".") | ForEach-Object { $DN += "DC=$_," }
    $DN = $DN.TrimEnd(",")

    $DHCPscope = $LabConfig.DHCPscope
    $ReverseDNSrecord = $DHCPscope -replace '^(\d+)\.(\d+)\.\d+\.(\d+)$','$3.$2.$1.in-addr.arpa'
    $DHCPscope = $DHCPscope.Substring(0,$DHCPscope.Length-1)
    $DCIP = ($DHCPscope+'10/24')

    #Create DSC configuration
    Configuration DCHydration {
        param (
            [Parameter(Mandatory)]
            [pscredential] $domainCred
        )

        Import-DscResource -ModuleName xActiveDirectory, xDNSServer, NetworkingDSC, xDHCPServer, PSDesiredStateConfiguration

        $safemodeAdministratorCred = $domainCred
        $NewADUserCred = $domainCred

        Node 'localhost' {
            WindowsFeature ADDSInstall {
                Ensure = "Present"
                Name = "AD-Domain-Services"
            }

            'GPMC', 'RSAT-AD-PowerShell', 'RSAT-AD-AdminCenter', 'RSAT-ADDS-Tools', 'RSAT-DNS-Server', 'DHCP', 'RSAT-DHCP' | Foreach-Object {
                $thisFeatureToLower = $_.Replace('-', '_')

                WindowsFeature $thisFeatureToLower {
                    Ensure = 'Present'
                    Name   = $_
                    DependsOn = '[WindowsFeature]ADDSInstall'
                }
            }

            xADDomain FirstDS {
                DomainName = $LabConfig.DomainName
                DomainAdministratorCredential = $domainCred
                SafemodeAdministratorPassword = $safemodeAdministratorCred
                DomainNetbiosName = $LabConfig.DomainNetbiosName
                DependsOn = '[WindowsFeature]ADDSInstall'
            }

            xADUser Domain_Admin {
                DomainAdministratorCredential = $domainCred
                Ensure      = 'Present'
                DomainName  = $LabConfig.DomainName
                UserName    = $LabConfig.DomainAdminName
                Password    = $NewADUserCred
                Description = 'DomainAdmin'
                PasswordNeverExpires = $true
                DependsOn = '[xADDomain]FirstDS'
            }

            xADGroup DomainAdmins {
                GroupName = 'Domain Admins'
                MembersToInclude = $LabConfig.DomainAdminName
                DependsOn = '[xADUser]Domain_Admin'
            }

            xADUser AdministratorNeverExpires {
                DomainName = $LabConfig.DomainName
                UserName = "Administrator"
                Ensure = "Present"
                DependsOn = "[xADDomain]FirstDS"
                PasswordNeverExpires = $true
            }

            IPaddress IP {
                IPAddress = $DCIP
                AddressFamily = 'IPv4'
                InterfaceAlias = 'Ethernet'
            }

            Service DHCPServer {
                Name = 'DHCPServer'
                State = 'Running'
                DependsOn =  '[WindowsFeature]DHCP'
            }

            xDhcpServerScope ManagementScope {
                Ensure        = 'Present'
                ScopeId       = ($DHCPscope + '0')
                IPStartRange  = ($DHCPscope + '11')
                IPEndRange    = ($DHCPscope + '254')
                Name          = 'ManagementScope'
                SubnetMask    = '255.255.255.0'
                LeaseDuration = '00:05:00'
                State         = 'Active'
                AddressFamily = 'IPv4'
                DependsOn = '[Service]DHCPServer'
            }

            xDhcpServerOption MgmtScopeRouterOption {
                Ensure    = 'Present'
                ScopeID   = ($DHCPscope + '0')
                DnsDomain = $Node.DomainName

                DnsServerIPAddress = ($DHCPscope + '10')
                AddressFamily      = 'IPv4'

                Router    = ($DHCPscope + '1')
                DependsOn = '[Service]DHCPServer'
            }

            xDhcpServerAuthorization LocalServerActivation { Ensure = 'Present' }

            xDnsServerADZone addReverseADZone {
                Name = $ReverseDNSrecord
                DynamicUpdate = "Secure"
                ReplicationScope = "Forest"
                Ensure = "Present"
                DependsOn = "[xDhcpServerOption]MgmtScopeRouterOption"
            }
        }
    }

    $ConfigData = @{
        AllNodes = @(
            @{
                Nodename = 'localhost'
                Role     = 'Parent DC'
                DomainAdminName   = $LabConfig.DomainAdminName
                DomainName        = $LabConfig.DomainName
                DomainNetbiosName = $LabConfig.DomainNetbiosName
                DomainDN          = $DN[0] + ',' + $DN[1]
                RegistrationKey   = '14fc8e72-5036-4e79-9f89-5382160053aa'
                PSDscAllowPlainTextPassword = $true
                PsDscAllowDomainUser= $true
                RetryCount = 50
                RetryIntervalSec = 30
            }
        )
    }

    #create LCM config
    [DSCLocalConfigurationManager()]
    Configuration LCMConfig {
        Node 'localhost' {
            Settings {
                RebootNodeIfNeeded = $true
                ActionAfterReboot = 'ContinueConfiguration'
            }
        }
    }

    #create DSC MOF files
    Write-Host "`t Creating DSC Configs for DC"
    LCMConfig   -OutputPath "$VMPath\buildData\config" -ConfigurationData $ConfigData -InformationAction SilentlyContinue | Out-Null

    #TODO: Got to here last night
    DCHydration -OutputPath "$VMPath\buildData\config" -ConfigurationData $ConfigData -domainCred $localCred -InformationAction SilentlyContinue | Out-Null

    If (-not (test-path "$VMPath\buildData\config\localhost.meta.mof")) { Write-Error 'Domain Controller LCM MOF creation failed' }
    If (-not (test-path "$VMPath\buildData\config\localhost.mof"))      { Write-Error 'Domain Controller Config MOF creation failed' }
}

#Create Domain Controller VM and vSwitch for lab
Function Add-LabVirtualMachines {
    $Switchname   = $LabConfig.SwitchName
    $SwitchExists = (Get-VMSwitch -Name "$($LabConfig.Prefix)-$($LabConfig.Switchname)*" -ErrorAction SilentlyContinue)

    if (-not ($SwitchExists)) {
        $SwitchGuid = $(((New-Guid).Guid).Substring(0,10))
        $SwitchName = "$($LabConfig.Prefix)-$($LabConfig.Switchname)_$SwitchGuid"

        Write-Host "`t Creating switch $Switchname"
        $VMSwitch = New-VMSwitch -SwitchType Internal -Name $Switchname

        Rename-NetAdapter -Name "*$($LabConfig.Prefix)-$($LabConfig.Switchname)*" -NewName "NATGW-$($LabConfig.Prefix)-$($LabConfig.Switchname)"

        $GatewayIP = "$($LabConfig.DHCPscope.Substring(0,$LabConfig.DHCPscope.Length-1))1"
        New-NetIPAddress -IPAddress $GatewayIP -PrefixLength 24 -InterfaceAlias "NATGW-$($LabConfig.Prefix)-$($LabConfig.Switchname)"
    }

    # If existing NAT is named wrong, delete then readd; else create the NAT
    $ExistingNat = Get-NetNat | Where-Object InternalIPInterfaceAddressPrefix -like "$($LabConfig.DHCPScope)*"

    If ($ExistingNat.Name -ne "Nat-$($LabConfig.Prefix)-$($LabConfig.Switchname)") {
        Get-NetNat | Where InternalIPInterfaceAddressPrefix -like "$($LabConfig.DHCPScope)*" | Remove-NetNat -Confirm:$false
        New-NetNat -Name "NAT-$($LabConfig.Prefix)-$($LabConfig.Switchname)" -InternalIPInterfaceAddressPrefix ($LabConfig.DHCPscope + "/24")
    }

    $LabConfig.VMs | ForEach-Object {
        $VM = Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue

        If ($VM) { Write-Host "`t VM named $($LabConfig.Prefix)$($_.VMName) already exists" }
        else {
            Write-Host "`t Creating VM: $($LabConfig.Prefix)$($_.VMName)"
            $VM = New-VM -Name "$($LabConfig.Prefix)$($_.VMName)" -MemoryStartupBytes $_.MemoryStartupBytes -Path $vmpath -SwitchName "$($LabConfig.Prefix)-$($LabConfig.Switchname)*" -Generation 2
            New-VHD -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ParentPath $VHDPath -Differencing -ErrorAction SilentlyContinue | Out-Null
            $BootDevice = Add-VMHardDiskDrive -VMName "$($LabConfig.Prefix)$($_.VMName)" -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -Passthru -ErrorAction SilentlyContinue
            Set-VMFirmware -VMName "$($LabConfig.Prefix)$($_.VMName)" -BootOrder $BootDevice
            Set-VHD -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ParentPath $VHDPath -IgnoreIdMismatch -ErrorAction SilentlyContinue
        }


        Set-VMProcessor -VMName "$($LabConfig.Prefix)$($_.VMName)" -Count 4 -ExposeVirtualizationExtensions $true
        Set-VMMemory    -VMName "$($LabConfig.Prefix)$($_.VMName)" -DynamicMemoryEnabled $true
        Set-VMFirmware  -VMName "$($LabConfig.Prefix)$($_.VMName)" -EnableSecureBoot Off
        Set-VM          -VMName "$($LabConfig.Prefix)$($_.VMName)"  -CheckpointType Production -AutomaticCheckpointsEnabled $false
        Enable-VMIntegrationService -VMName "$($LabConfig.Prefix)$($_.VMName)" -Name 'Guest Service Interface'
    }
}

Function Get-LabVMs {
    $AllVMs = @()
    $AzureStackHCIVMs = @()

    $LabConfig.VMs | ForEach-Object {
        $AllVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)"
    }

    $LabConfig.VMs.Where{$_.Role -eq 'AzureStackHCI'} | ForEach-Object {
        $AzureStackHCIVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)"
    }

    Return $AllVMs, $AzureStackHCIVMs
}

Function Assert-LabDomain {
    $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' } | Foreach-Object {
        $DCName = "$($LabConfig.Prefix)$($_.VMName)"
    }

    # Use local cred
    Invoke-Command -VMName $DCName -Credential $localCred -ScriptBlock {
        $InitialStatus = Get-DscConfigurationStatus -ErrorAction SilentlyContinue
        $LCM           = Get-DSCLocalConfigurationManager -ErrorAction SilentlyContinue

        if ($InitialStatus -eq $null -and $LCM.LCMState -eq 'Idle' ) {
            Set-DscLocalConfigurationManager -Path "$($using:VMPath)\buildData\config"          -Force -InformationAction SilentlyContinue -WarningAction SilentlyContinue
            Start-DscConfiguration           -Path "$($using:VMPath)\buildData\config" -Verbose -Force -InformationAction SilentlyContinue -WarningAction SilentlyContinue
        }
    }
}

Function Wait-ForAzureStackHCIDomain {
    #TODO: Remove duplicate declaration; Also in Assert-LabDomain
    $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' } | Foreach-Object {
        $DCName = "$($LabConfig.Prefix)$($_.VMName)"
    }

    do {
        # Use local cred until domain is created
        $DscConfigurationStatus = Invoke-Command -VMName $DCName -ScriptBlock {
            Get-DscConfigurationStatus -ErrorAction SilentlyContinue
        } -Credential $localCred -ErrorAction SilentlyContinue

        $DSCLocalConfigurationManager = Invoke-Command -VMName $DCName -ScriptBlock {
            Get-DSCLocalConfigurationManager -ErrorAction SilentlyContinue
        } -Credential $localCred -ErrorAction SilentlyContinue

# This should be status -ne Success
        if ($DscConfigurationStatus.Status -ne 'Success') {
            Write-Host "`t Domain Controller Configuration in Progress. Sleeping for 20 seconds...Yaaaawwwwwnnnn..."

            If ($DSCLocalConfigurationManager.LCMState -eq $null) { Write-Host "`t `t LCM State : Unknown - Machine may be rebooting `n" }
            Else {
                Write-Host "`t `t LCM State : $($DSCLocalConfigurationManager.LCMState)"
                Write-Host "`t `t LCM Detail: $($DSCLocalConfigurationManager.LCMStateDetail) `n"
            }

            Start-Sleep 20
        } ElseIf ($DscConfigurationStatus.status -eq "Success" -and $DscConfigurationStatus.Type -ne 'LocalConfigurationManager' ) {
            Write-Host "`t Current Domain state: $($DscConfigurationStatus.status), ResourcesNotInDesiredState: $($DscConfigurationStatus.resourcesNotInDesiredState.count), ResourcesInDesiredState: $($DscConfigurationStatus.resourcesInDesiredState.count)"
            Write-Host "`t `t Domain $($LabConfig.DomainName) configured successfully `n"
        }

        #$i++
    } until ($DscConfigurationStatus.Status -eq 'Success' -and $DscConfigurationStatus.rebootrequested -eq $false)

    $DHCPScope = $LabConfig.DHCPscope

    # Use domain cred
    Invoke-Command -VMName $DCName -Credential $VMCred -ErrorAction SilentlyContinue -ScriptBlock {
        # Add reverse lookup zone (as setting reverse lookup does not work with DSC)
        Add-DnsServerPrimaryZone -NetworkID ($Using:DHCPscope + "/24") -ReplicationScope "Forest"

        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12' -Name ConfigurationState -Value 2
    }
}
#endregion


Function Remove-AzureStackHCIVMHardware {
    # Cleanup; Remove existing drives (except OS); Remove existing NICs (except OS)

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Start-RSJob -Name "$($thisVM.Name)-VMHardware Cleanup" -ScriptBlock {
            $thisJobVM = $using:thisVM

            Get-VMScsiController -VMName $thisJobVM.Name | ForEach-Object {
                $thisSCSIController = $_

                [Console]::WriteLine("`t Removing old drives from: $($thisJobVM.Name)")
                $thisSCSIController.Drives | ForEach-Object {
                    $thisVMDrive = $_

                    if (-not ($thisVMDrive.ControllerNumber -eq 0 -and $thisVMDrive.ControllerLocation -eq 0)) { $thisVMDrive | Remove-VMHardDiskDrive }
                }

                if ($thisSCSIController.ControllerNumber -ne 0) {
                    [Console]::WriteLine("`t `t Removing old SCSI controllers for: $($thisJobVM.Name)")
                    Remove-VMScsiController -VMName $thisJobVM.Name -ControllerNumber 1
                }
            }

            [Console]::WriteLine("`t Removing virtual adapters from: $($thisJobVM.Name)")
            Get-VMNetworkAdapter -VMName $thisJobVM.Name | ForEach-Object { Remove-VMNetworkAdapter -VMName $thisJobVM.Name }
        } | Out-Null
    }
}

# Create and attach new drives; then adapters
Function New-AzureStackHCIVMS2DDisks {
    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Start-RSJob -Name "$($thisVM.Name)-CreateAndAttachDisks" -ScriptBlock {
            $thisJobVM = $using:thisVM

            #Note: After Lab Environment is deployed, there should be 1 SCSI controller for the OSD.
            #      This step will add 3 more. If this gets messed up re-run lab environment setup.
            [Console]::WriteLine("`t Creating SCSI Controllers for $($thisJobVM.Name)")
            1..3 | Foreach-Object { Add-VMScsiController -VMName $thisJobVM.Name -ErrorAction SilentlyContinue }

            # Remove all the old drives and recreate. Simpler than checking that each disk hasn't been used.
            #Note: This may not work once the checkpoints are introduced.
            $thisVMPath = Join-path $thisJobVM.Path 'Virtual Hard Disks\DataDisks'
            Remove-Item -Path $thisVMPath -Recurse -Force -ErrorAction SilentlyContinue

            $SCMPath = New-Item -Path (Join-Path $thisVMPath 'SCM') -ItemType Directory -Force
            $SSDPath = New-Item -Path (Join-Path $thisVMPath 'SSD') -ItemType Directory -Force
            $HDDPath = New-Item -Path (Join-Path $thisVMPath 'HDD') -ItemType Directory -Force

            $thisJobLabConfig = $using:LabConfig
            $theseSCMDrives   = $thisJobLabConfig.VMs.Where{$thisJobVM.Name -like "*$($_.VMName)"}.SCMDrives
            $theseSSDDrives   = $thisJobLabConfig.VMs.Where{$thisJobVM.Name -like "*$($_.VMName)"}.SSDDrives
            $theseHDDDrives   = $thisJobLabConfig.VMs.Where{$thisJobVM.Name -like "*$($_.VMName)"}.HDDDrives

            [Console]::WriteLine("`t Creating drives for $($thisJobVM.Name)")
            [Console]::WriteLine("`t `t Creating SCM Drives for $($thisJobVM.Name)")
            $theseSCMDrives | ForEach-Object {
                $thisDrive = $_
                0..($theseSCMDrives.Count - 1) | ForEach-Object { New-VHD -Path "$SCMPath\$($thisJobVM.Name)-SCM-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null }

                #Note: Keep this separate to avoid disk creation race
                0..($theseSCMDrives.Count - 1) | ForEach-Object {
                    [Console]::WriteLine("`t Attaching SCM Drive from: $($SCMPath)\$($thisJobVM.Name)-SCM-$_.VHDX")
                    Add-VMHardDiskDrive -VMName $thisJobVM.Name -Path "$SCMPath\$($thisJobVM.Name)-SCM-$_.VHDX" -ControllerType SCSI -ControllerNumber 1 -ControllerLocation $_ -ErrorAction SilentlyContinue | Out-Null
                }
            }

            [Console]::WriteLine("`t `t Creating SSD Drives for $($thisJobVM.Name)")
            $theseSSDDrives | ForEach-Object {
                $thisDrive = $_

                0..($theseSSDDrives.Count - 1) | ForEach-Object { New-VHD -Path "$SSDPath\$($thisJobVM.Name)-SSD-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null }

                #Note: Keep this separate to avoid disk creation race
                0..($theseSSDDrives.Count - 1) | ForEach-Object {
                    [Console]::WriteLine("`t Attaching SSD Drive from: $($SSDPath)\$($thisJobVM.Name)-SSD-$_.VHDX")
                    Add-VMHardDiskDrive -VMName $thisJobVM.Name -Path "$SSDPath\$($thisJobVM.Name)-SSD-$_.VHDX" -ControllerType SCSI -ControllerNumber 2 -ControllerLocation $_ -ErrorAction SilentlyContinue | Out-Null
                }
            }

            [Console]::WriteLine("`t `t Creating HDD Drives for $($thisJobVM.Name)")
            $theseHDDDrives | ForEach-Object {
                $thisDrive = $_

                0..($theseHDDDrives.Count - 1) | ForEach-Object { New-VHD -Path "$HDDPath\$($thisJobVM.Name)-HDD-$_.VHDX" -Dynamic -SizeBytes $thisDrive.Size -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null }

                0..($theseHDDDrives.Count - 1) | ForEach-Object {
                    [Console]::WriteLine("`t Attaching HDD Drive from: $($HDDPath)\$($thisJobVM.Name)-HDD-$_.VHDX")
                    Add-VMHardDiskDrive -VMName $thisJobVM.Name -Path "$HDDPath\$($thisJobVM.Name)-HDD-$_.VHDX" -ControllerType SCSI -ControllerNumber 3 -ControllerLocation $_ -ErrorAction SilentlyContinue | Out-Null
                }
            }
        } | Out-Null
    }
}

Function Set-AzureStackHCIDiskMediaType {
    #this isn't persisted so it needs to be run each time the system is rebooted.
    # Create a schtask in the future
    # Make sure to detec if the disk is actually local because once S2D is enabled, you'll see every disk from each node and rename improperly otherwise.

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        #Note: Due to issue with Set-PhysicalDisk, mediatype/name is reset after a reboot; reset prior to creating cluster
        $theseSCMDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.SCMDrives.Size
        $theseSSDDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.SSDDrives.Size
        $theseHDDDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.HDDDrives.Size

        Write-Host "Setting media type for the disks again. Disks are renamed after a reboot for some reason..."
        Invoke-Command -VMName $thisVM.Name -Credential $VMCred -ScriptBlock {
            Get-PhysicalDisk | Where-Object Size -eq $using:theseSCMDrivesSize | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "$($env:ComputerName)-PMEM$($_.DeviceID)" -MediaType SCM
            }

            Get-PhysicalDisk | Where-Object Size -eq $using:theseSSDDrivesSize | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "$($env:ComputerName)-SSD$($_.DeviceID)" -MediaType SSD
            }

            Get-PhysicalDisk | Where-Object Size -eq $using:theseHDDDrivesSize | Sort-Object Number | ForEach-Object {
                Set-PhysicalDisk -UniqueId $_.UniqueID -NewFriendlyName "$($env:ComputerName)-HDD$($_.DeviceID)" -MediaType HDD
            }
        }
    }
}

Function New-AzureStackHCIVMAdapters {

    <#Note: May not be needed since this will be done while the VMs are on
    #Note: Start to get a MAC on the vNICs to sort them in the future
    Reset-AzStackVMs -Start -VMs $AzureStackHCIVMs
    Reset-AzStackVMs -Stop -VMs  $AzureStackHCIVMs
    #>

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_
        Start-RSJob -Name "$($thisVM.Name)-ConfigureAdapters" -ScriptBlock {
            $thisJobVM = $using:thisVM
            $thisJobLabConfig = $using:LabConfig

            [Console]::WriteLine("Creating adapters for $($thisJobVM.Name)")
            $theseAdapters = $thisJobLabConfig.VMs.Where{$thisJobVM.Name -like "*$($_.VMName)"}.Adapters

            #Note: There shouldn't be any NICs in the system at this point, so just add however many you in $theseAdapters
            1..$theseAdapters.Count | Foreach-Object {
                Add-VMNetworkAdapter -VMName $thisJobVM.Name -SwitchName "$($thisJobLabConfig.Prefix)-$($thisJobLabConfig.SwitchName)*"
            }

            # Enable Device Naming; attach to the vSwitch; Trunk all possible vlans so that we can set a vlan inside the VM
            $vmAdapters = Get-VMNetworkAdapter -VMName $thisJobVM.Name | Sort-Object MacAddress

            [Console]::WriteLine("`t Enabling device naming and trunking vlans for vmNICs for: $($thisJobVM.Name)")
            $vmAdapters | ForEach-Object {
                Set-VMNetworkAdapter -VMNetworkAdapter $_ -DeviceNaming On
                Set-VMNetworkAdapterVlan -VMName $thisJobVM.Name -VMNetworkAdapterName $_.Name -Trunk -AllowedVlanIdList 1-4094 -NativeVlanId 0
            }

            #Separate this section
            #Note: Naming the first 2 Mgmt for easy ID. This can be updated; just trying to keep it simple
            [Console]::WriteLine("`t Renaming vmNICs for propagation through to the $($thisJobVM.Name)")

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
        } | Out-Null
    }

    Get-RSJob | Where-Object Name -like "*-ConfigureAdapters" | Wait-RSJob | Out-Null
}
