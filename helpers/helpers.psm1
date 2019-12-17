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
        ServerISOFolder   = 'C:\Datastore\19537.1000.191212-1425.rs_prerelease_SERVER_VOL_x64FRE_en-us.iso'

        # This is the name of the switch to attach VMs to. This lab has DHCP so either make a private/internal vSwitch or i'm going to takeover your network
        # If the specified switch doesn't exist a private switch will be created AzureStackHCILab-Guid
        DHCPscope     = '10.0.0.0'
        SwitchName = 'AzureStackHCILab'
        VMs = @()
    }

    1..2 | ForEach-Object {
        $LABConfig.VMs += @{
            VMName        = "0$_"

            # This should always be AzureStackHCI
            Role = 'AzureStackHCI'
            MemoryStartupBytes = 2GB

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
<#
    #TODO: Build a W10 WAC System
    $LABConfig.VMs += @{
        VMName        = 'WAC01'

        # This should always be WAC
        Role          = 'WAC'
        MemoryStartupBytes = 8GB
    }#>

    $LABConfig.VMs += @{
        VMName        = 'DC01'

        # This should always be Domain Controller
        Role          = 'Domain Controller'
        MemoryStartupBytes = 1GB
    }

    # No touchie! Required but no mods needed - Prep local and domain creds
    $LabConfig.DomainNetbiosName = ($LabConfig.DomainName.Split('.')[0])
    $global:pass   = ConvertTo-SecureString $($LabConfig.AdminPassword) -AsPlainText -Force
    $global:VMCred = New-Object System.Management.Automation.PSCredential ("$($LabConfig.DomainName)\$($LabConfig.DomainAdminName)", $pass)
    $global:localCred = New-Object System.Management.Automation.PSCredential ('.\Administrator', $pass)

    $LabConfig
}

#region Used for VM/Lab configuration
function Wait-ForHeartbeatState {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('On', 'Off')]
        [string] $State ,

        [Microsoft.HyperV.PowerShell.VirtualMachine[]] $VMs
    )

    Switch ($State) {
        'On' {
            $VMs | ForEach-Object {
                While ((Get-VMIntegrationService -VMName $_.Name -Name Heartbeat).PrimaryStatusDescription -ne 'Ok') {
                    Write-Host "`t Waiting on Heartbeat for: $($_.Name)"
                    Write-Host "`t `t Getting sleepy..."
                    Start-Sleep -Seconds 5
                }

                Write-Host "`t Ensuring PowerShell Direct is ready for: $($_.Name)"

                do {
                    Write-Host "`t `t Checking PowerShell Direct on $($_.Name)...Getting sleepy again"
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
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

<settings pass="offlineServicing">
<component
    xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    language="neutral"
    name="Microsoft-Windows-PartitionManager"
    processorArchitecture="amd64"
    publicKeyToken="31bf3856ad364e35"
    versionScope="nonSxS"
    >
    <SanPolicy>1</SanPolicy>
</component>
</settings>
<settings pass="specialize">
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <ComputerName>*</ComputerName>
    <RegisteredOwner>$($LabConfig.DomainAdminName)</RegisteredOwner>
    <RegisteredOrganization>$($LabConfig.DomainNetbiosName)</RegisteredOrganization>
</component>
</settings>
<settings pass="oobeSystem">
<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
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
</unattend>

"@

    Set-Content -path $unattendFile -value $fileContent

    #return the file object
    Return $unattendFile
}

#Customize Base Disk
Function Initialize-BaseDisk {
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

                New-Item -Path "$MountPath\Windows\Panther" -ItemType Directory -Force -InformationAction SilentlyContinue
                Use-WindowsUnattend -Path $MountPath -UnattendPath $unattendfile -InformationAction SilentlyContinue

                'xActiveDirectory', 'xDNSServer', 'NetworkingDSC', 'xDHCPServer', 'xPSDesiredStateConfiguration' | foreach-Object {
                    $thisModule = $_

                    start-rsjob -Name "$thisModule-Modules" -ScriptBlock {
                        Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\$($using:thisModule)" -Destination "$MountPath\Program Files\WindowsPowerShell\Modules\" -Recurse -Force
                    }
                }

                Get-RSJob | Wait-RSJob
                Get-RSJob | Remove-RSJob

                Copy-Item -Path $unattendfile -Destination "$MountPath\Windows\Panther\unattend.xml" -Force
            }
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
    $DCIP = ($DHCPscope+"1/24")

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
                DomainName = $LabConfig.DomainName
                DomainAdministratorCredential = $domainCred
                UserName = $LabConfig.DomainAdminName
                Password = $NewADUserCred
                Ensure = "Present"
                Description = "DomainAdmin"
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
                IPStartRange  = ($DHCPscope + '10')
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
                ScopeID   = ($DHCPscope+"0")
                DnsDomain = $Node.DomainName

                DnsServerIPAddress = ($DHCPscope+"1")
                AddressFamily      = 'IPv4'

                Router    = ($DHCPscope+"1")
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

    If ($ConfigData -eq $null) {
        Write-Error "ConfigData could not be generated for some reason, this will prevent the creation of the MOF file...Please investigate" -ErrorAction Stop
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
    $SwitchExists = (Get-VMSwitch -Name "$($LabConfig.Switchname)*" -ErrorAction SilentlyContinue)

    if (-not ($SwitchExists)) {
        $SwitchGuid = $(((New-Guid).Guid).Substring(0,18))
        $SwitchName = "AzureStackHCILabSwitch_$SwitchGuid"

        Write-Host "`t Creating switch $Switchname"
        New-VMSwitch -SwitchType Private -Name $Switchname | Out-Null
    }

    $LabConfig.VMs | ForEach-Object {
        $VM = Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue

        If ($VM) { Write-Host "`t VM named $($LabConfig.Prefix)$($_.VMName) already exists" }
        else {
            Write-Host "`t Creating VM: $($LabConfig.Prefix)$($_.VMName)"
            $VM = New-VM -Name "$($LabConfig.Prefix)$($_.VMName)" -MemoryStartupBytes $_.MemoryStartupBytes -Path $vmpath -SwitchName "$Switchname*" -Generation 2
            New-VHD -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ParentPath $VHDPath -Differencing -ErrorAction SilentlyContinue | Out-Null
            $BootDevice = Add-VMHardDiskDrive -VMName "$($LabConfig.Prefix)$($_.VMName)" -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -Passthru -ErrorAction SilentlyContinue
            Set-VMFirmware -VMName "$($LabConfig.Prefix)$($_.VMName)" -BootOrder $BootDevice
            Set-VHD -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ParentPath $VHDPath -IgnoreIdMismatch -ErrorAction SilentlyContinue
        }

        Set-VMProcessor -VMName "$($LabConfig.Prefix)$($_.VMName)" -Count 4
        Set-VMMemory    -VMName "$($LabConfig.Prefix)$($_.VMName)" -DynamicMemoryEnabled $true -MinimumBytes 2GB
        Set-VMFirmware  -VMName "$($LabConfig.Prefix)$($_.VMName)" -EnableSecureBoot Off
        Set-VM          -VMName "$($LabConfig.Prefix)$($_.VMName)" -AutomaticCheckpointsEnabled $false
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

    do {
        # Use local cred until domain is created
        #temp $DCName = 'AzStackHCIDC01'
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

Function Move-ToNewParentVHDX {
    param (
        #Takes a VM Object
        $VM ,

        #Takes a VMHardDiskDrive
        $VHDXToConvert
    )

    # This function will convert the differenced disk into a fixed disk
    $ParentPath   = Split-Path -Path $VHDXToConvert.Path -Parent
    $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath

    $BaseLeaf = Split-Path $BaseDiskPath -Leaf
    $NewBasePath = Join-Path -Path $ParentPath -ChildPath $BaseLeaf

    Write-Host "`t Copying $($VM.Name) BaseDisk to $NewBasePath"
    Copy-Item -Path $BaseDiskPath -Destination $NewBasePath -InformationAction SilentlyContinue

    $Global:BaseDiskACL = Get-ACL $BaseDiskPath

    Write-Host "`t Reparenting $($VM.Name) OSD to $NewBasePath"
    $VHDXToConvert | Set-VHD -ParentPath $NewBasePath -IgnoreIdMismatch
}

Function Convert-FromDiffDisk {
    param (
        #Takes a VM Object
        $VM ,

        #Takes a VMHardDiskDrive
        $VHDXToConvert
    )

    $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath
    Write-Host "`t Merging $($VM.Name) OSD to $($BaseDiskPath)"

    Set-ACL -Path $BaseDiskPath -AclObject $BaseDiskACL
    Set-ItemProperty -Path $BaseDiskPath -Name IsReadOnly -Value $false

    Merge-VHD -Path $VHDXToConvert.Path -DestinationPath $BaseDiskPath
    Remove-VMHardDiskDrive -VMName $VM.Name -ControllerNumber 0 -ControllerLocation 0 -ControllerType SCSI
    Add-VMHardDiskDrive -VM $VM -Path $BaseDiskPath -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -ErrorAction SilentlyContinue
}
