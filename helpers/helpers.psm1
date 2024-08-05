# These functions are not exported and you should not ever have to come here...
Function Approve-AzureStackHCILabState {
    $PASS = '+'
    $FAIL = '-'
    $testsFailed = 0

    Write-Host "Testing Host System ${$env:ComputerName}" -ForegroundColor Green

    # Test running elevated
    $isAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
    if ($isAdmin) { Write-Host "[$PASS] The window is running elevated" -ForegroundColor DarkCyan }
    else {
        Write-Host "[$FAIL] The window is running elevated" -ForegroundColor Red
        $testsFailed ++
    }

    $NodeOS = Get-CimInstance -ClassName 'Win32_OperatingSystem'

    ### Verify the Host is sufficient version
    if ([Version]$NodeOS.Version -ge 10.0.0) { Write-Host "[$PASS] System is running Windows 10 (Client or Server) or later" -ForegroundColor DarkCyan }
    else {
        Write-Host "[$FAIL] System is running Windows 10 (Client or Server) or later" -ForegroundColor Red
        $testsFailed ++
    }

    $RequiredMemory = ($LabConfig.VMs.MemoryStartupBytes | Measure-Object -Sum).Sum / 1GB + 2
    $AvailableMemory = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
    if ($RequiredMemory -lt $AvailableMemory) {
        Write-Host "[$PASS] Host system has enough memory to cover what's specified in LabConfig" -ForegroundColor DarkCyan
    }
    else {
        Write-Host "[$FAIL] Host system has enough memory to cover what's specified in LabConfig" -ForegroundColor Red
        $testsFailed ++
    }

    $RequiredModules = (Get-Module -Name AzureStackHCIJumpstart -ListAvailable).RequiredModules
    if ($RequiredModules) {
        $RequiredModules.GetEnumerator() | ForEach-Object {
            $thisModule = $_

            Remove-Variable module -ErrorAction SilentlyContinue
            $module = Get-Module $thisModule.Name -ListAvailable -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1

            # Required modules
            if ($module.Name) { Write-Host "[$PASS] The host system has the module [$($thisModule.Name)]" -ForegroundColor DarkCyan }
            else {
                Write-Host "[$FAIL] Host system has enough memory to cover what's specified in LabConfig" -ForegroundColor Red
                $testsFailed ++
            }

            # Required version of the modules
            if ($module.version -ge $_.ModuleVersion) { Write-Host "[$PASS] The host system version of the module [$($thisModule.Name)] is the correct version [$($thisModule.version)]" -ForegroundColor DarkCyan }
            else {
                Write-Host "[$FAIL] The host system version of the module [$($thisModule.Name)] is the wrong version." -ForegroundColor Red
                Write-Host "-- Expected Version: $($_.ModuleVersion)" -ForegroundColor Red
                Write-Host "-- Actual Version $($thisModule.version)" -ForegroundColor Red
                $testsFailed ++
            }
        }
    }

    Switch -Wildcard ($NodeOS.Caption) {
        "*Windows 10*" {
            $HyperVInstallationState = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V

            if ($HyperVInstallationState.State -eq 'Enabled') {
                Write-Host "${env:ComputerName} has the feature $($HyperVInstallationState.DisplayName) installed"  -ForegroundColor DarkCyan
            }
            else {
                Write-Host "${env:ComputerName} does not have the feature $($HyperVInstallationState.DisplayName) installed" -ForegroundColor Red
                $testsFailed ++
            }
        }

        Default {
            $HyperVInstallationState = (Get-WindowsFeature | Where-Object Name -like *Hyper-V* -ErrorAction SilentlyContinue)

            $HyperVInstallationState | ForEach-Object {
                if ( $_.InstallState -eq 'Installed' ) {
                    Write-Host "[$PASS] The host system has the feature [$($_.DisplayName)] installed" -ForegroundColor DarkCyan
                }
                else {
                    Write-Host "[$FAIL] The host system has NOT installed the feature [$($_.DisplayName)]" -ForegroundColor Red
                    $testsFailed ++
                }
            }
        }
    }

    Write-Host 'Testing Lab Config (Get-AzureStackHCILabConfig)' -ForegroundColor Green

    # One nodes or more in the lab config
    'WAC', 'Domain Controller' | Foreach-Object {
        $thisRole = $_
        if (($LabConfig.VMs.Where{$_.Role -eq "$thisRole" }).Count -ge 1) {
            Write-Host "[$PASS] The Get-AzureStackHCILabConfig function specifies at least one machine with the role $_" -ForegroundColor DarkCyan
        }
        else {
            Write-Host "[$FAIL] The Get-AzureStackHCILabConfig function specifies at least one machine with the role $_" -ForegroundColor Red
            $testsFailed ++
        }
    }

    # Two nodes or more in the lab config
    'AzureStackHCI' | Foreach-Object {
        $thisRole = $_
        if (($LabConfig.VMs.Where{$_.Role -eq $thisRole }).Count -ge 2) {
            Write-Host "[$PASS] The Get-AzureStackHCILabConfig function specifies at least one machine with the role $_" -ForegroundColor DarkCyan
        }
        else {
            Write-Host "[$FAIL] The Get-AzureStackHCILabConfig function specifies at least one machine with the role $_" -ForegroundColor Red
            $testsFailed ++
        }
    }

    # DHCP scope specified in labconfig is not in use on this machine
    $DHCPScopePrefix = $LabConfig.DHCPScope | foreach-Object { ([ipaddress]$_).GetAddressBytes()[0..2] -join '.' }
    $ExistingSwitch = "NATGW-$($LabConfig.Prefix)-$($LabConfig.SwitchName)"
    $InUseAddress = Get-NetIPAddress | Where {$_.IPAddress -like "$DHCPScopePrefix*" -and $_.InterfaceAlias -ne $ExistingSwitch}

    if (-not($InUseAddress)) {
        Write-Host "[$PASS] The DHCP Scope in the Get-AzureStackHCILabConfig function does not conflict with any already in use on this machine." -ForegroundColor DarkCyan
    }
    else {
        Write-Host "[$FAIL] The Get-AzureStackHCILabConfig function specifies a DHCP Scope that is in use on this machine." -ForegroundColor Red
        $testsFailed ++
    }

    # Ensure WS base disks actually exist
    if (Test-Path $LabConfig.BaseVHDX_WS) {
        Write-Host "[$PASS] The Windows Server Base VHDX specified in the lab config file actually exists" -ForegroundColor DarkCyan
    }
    else {
        Write-Host "[$FAIL] The Windows Server Base VHDX specified in the lab config file does not exist" -ForegroundColor Red
        $testsFailed ++
    }

    # Ensure HCI base disks actually exist
    if (Test-Path $LabConfig.BaseVHDX_HCI) {
        Write-Host "[$PASS] The Azure Stack HCI Base VHDX specified in the lab config file actually exists" -ForegroundColor DarkCyan
    }
    else {
        Write-Host "[$FAIL] The Azure Stack HCI Base VHDX specified in the lab config file does not exist" -ForegroundColor Red
        $testsFailed ++
    }

    # Ensure WS base disks are not read only
    if (-not ((Get-Item $LabConfig.BaseVHDX_WS).IsReadOnly)) {
        Write-Host "[$PASS] The Windows Server Base VHDX specified in the lab config is writeable" -ForegroundColor DarkCyan
    }
    else {
        Write-Host "[$FAIL] The Windows Server Base VHDX specified in the lab config file is read-only" -ForegroundColor Red
        $testsFailed ++
    }

    # Ensure WS base disks are not read only
    if (-not ((Get-Item $LabConfig.BaseVHDX_HCI).IsReadOnly)) {
        Write-Host "[$PASS] The Azure Stack HCI Base VHDX specified in the lab config is writeable" -ForegroundColor DarkCyan
    }
    else {
        Write-Host "[$FAIL] The Azure Stack HCI Base VHDX specified in the lab config file is read-only" -ForegroundColor Red
        $testsFailed ++
    }

    If ($testsfailed -gt 0) {
        Write-Error 'Prerequisite checks on the host have failed. Please review the output to identify the reason for the failures' -ErrorAction Stop
    }
}

#region reboot and VM management
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

                    # Give machines 2.5 minutes to startup if $IgnoreLoopCount -eq $false;
                    if ($TimesThroughLoop -eq 30) {
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
                    Write-Host "`t Waiting for $($_.Name) to shutdown."
                    Start-Sleep -Seconds 5
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
        $VMs | ForEach-Object { Stop-VM -VMName $_.Name -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue  }
        If ($Wait) { Wait-ForHeartbeatState -State Off -VMs $VMs }
    }

    If ($Stop) {
        $VMs | ForEach-Object { Stop-VM -VMName $_.Name -TurnOff -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }
        If ($Wait) { Wait-ForHeartbeatState -State Off -VMs $VMs }
    }
}
#endregion

#region Base Disk for VMs
Function New-BaseDisk {
    Write-Host "`t Mounting ISO for Hydration"
    $MountedISO     = Mount-DiskImage -ImagePath $LabConfig.ServerISO -PassThru -InformationAction SilentlyContinue
    $ISODriveLetter = "$((Get-Volume -DiskImage $MountedISO -InformationAction SilentlyContinue).DriveLetter):"
    $BuildNumber    = (Get-ItemProperty -Path (Join-Path -Path $ISODriveLetter -ChildPath "setup.exe") -InformationAction SilentlyContinue).VersionInfo.FileBuildPart
    $WindowsImage   = Get-WindowsImage -ImagePath (Join-Path -Path $ISODriveLetter -ChildPath "sources\install.wim") -InformationAction SilentlyContinue
    $Edition        = ($WindowsImage | Where-Object ImageName -like *Server*2019*Datacenter*Desktop*).ImageName
    $vhdname        = "BaseDisk_$BuildNumber.vhdx"
    $global:VHDPath = "$VMPath\$vhdname"

    Write-Host "`t The ISO provided contains build number: $BuildNumber"

    if (-not(Test-Path $VHDPath)) {
        Write-Host "`t Hydrating VHDX...Please be patient"

        Convert-WindowsImage -SourcePath "$ISODriveLetter\sources\install.wim" -Edition $Edition -VHDPath $VHDPath -SizeBytes 100GB -VHDFormat VHDX -DiskLayout UEFI | Out-Null
    }

    Write-Host "`t Dismounting ISO Image"
    Dismount-DiskImage -ImagePath $LabConfig.ServerISO -InformationAction SilentlyContinue | Out-Null
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

    $unattendFile = New-Item "$Path\Unattend.xml" -ItemType File -Force
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
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>Administrator</Username>
            </AutoLogon>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>$($LabConfig.AdminPassword)</Value>
                    <PlainText>true</PlainText>
                    <Enabled>true</Enabled>
                </AdministratorPassword>
            </UserAccounts>
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <SkipMachineOOBE>true</SkipMachineOOBE>
                <SkipUserOOBE>true</SkipUserOOBE>
                <ProtectYourPC>3</ProtectYourPC>
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
Function Initialize-HCIBaseDisk {
    # Create Unattend File; remove old unattend
    $TimeZone  = (Get-TimeZone).id
    Remove-Item -Path "$VMPath\buildData\Unattend.xml" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$VMPath\buildData\HCIBaseDisk_unattend.xml" -Force -ErrorAction SilentlyContinue
    $unattendFile = New-UnattendFileForVHD -TimeZone $TimeZone -AdminPassword $LabConfig.AdminPassword -Path "$VMPath\buildData"

    #Apply Unattend to VM
    Write-Host "`t Applying Unattend for HCI Base Disk"
    $unattendfile = $unattendFile.FullName

    If ($LabConfig.BaseVHDX_HCI) { $global:HCIVHDPath = $LabConfig.BaseVHDX_HCI }

    If ( Test-Path $HCIVHDPath ) {
        Dismount-DiskImage -ImagePath $HCIVHDPath -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
        $MountedDisk = Mount-DiskImage -ImagePath $HCIVHDPath -StorageType VHDX -ErrorAction SilentlyContinue

        If ( $($MountedDisk.Attached) -eq $true ) {
            $DriveLetter = $(Get-DiskImage -ImagePath $HCIVHDPath | Get-Disk | Get-Partition | Get-Volume).DriveLetter
            $MaxSize = (Get-PartitionSupportedSize -DriveLetter $DriveLetter -ErrorAction SilentlyContinue).sizeMax

            #TODO: Make sure not the same size as the drives included in LabConfig
            Switch ($MaxSize) {
                {$_ -lt 100GB} {
                    Dismount-DiskImage -ImagePath $HCIVHDPath -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
                    Resize-VHD -Path $HCIVHDPath -SizeBytes (100GB)

                    #Note: Redo all this stuff in case the drive letters changed
                    $MountedDisk = Mount-DiskImage -ImagePath $HCIVHDPath -StorageType VHDX -ErrorAction SilentlyContinue
                    $DriveLetter = $(Get-DiskImage -ImagePath $HCIVHDPath | Get-Disk | Get-Partition | Get-Volume).DriveLetter

                    Resize-Partition -DriveLetter $DriveLetter -Size $MaxSize -ErrorAction SilentlyContinue
                }
            }

            Remove-Variable MaxSize -ErrorAction SilentlyContinue
            $MountPath = "$($DriveLetter):" -replace ' '

            If ( Test-Path "$MountPath\Windows\Panther\unattend.xml" ) { Write-Host "`t Unattend file exists..." }
            Else {
                Write-Host "`t Unattend file does not exist...Updating..."

                New-Item -Path "$MountPath\Windows\Panther" -ItemType Directory -Force | Out-Null
                Use-WindowsUnattend -Path $MountPath -UnattendPath $unattendfile -InformationAction SilentlyContinue

                Copy-Item -Path $unattendfile -Destination "$MountPath\Windows\Panther\unattend.xml" -Force
            }
        }
        Else { Write-Host "`t $HCIVHDPath could not be mounted but was found (likely in use)" }
    }
    Else { Write-Error "$HCIVHDPath was not found - Can't hydrate the basedisk" -ErrorAction Stop }

    Dismount-DiskImage -ImagePath $HCIVHDPath -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
    Set-ItemProperty -Path $HCIVHDPath -Name IsReadOnly -Value $true

    Rename-Item -Path $unattendfile -NewName "$VMPath\buildData\HCIBaseDisk_unattend.xml"
}

Function Initialize-WSBaseDisk {
    # Create Unattend File; remove old unattend
    $TimeZone  = (Get-TimeZone).id
    Remove-Item -Path "$VMPath\buildData\Unattend.xml" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$VMPath\buildData\WSBaseDisk_unattend.xml" -Force -ErrorAction SilentlyContinue
    New-UnattendFileForVHD -TimeZone $TimeZone -AdminPassword $LabConfig.AdminPassword -Path "$VMPath\buildData"

    #Apply Unattend to VM
    Write-Host "`t Applying Unattend and copying DSC Modules for WS Base Disk"
    $unattendfile = "$VMPath\buildData\Unattend.xml"

    # If using ServerISO, this is set Function:\New-BaseDisk. If using BaseVHDX, this needs to be set
    If ($LabConfig.BaseVHDX_WS) { $global:WSVHDPath = $LabConfig.BaseVHDX_WS }

    If ( Test-Path $WSVHDPath ) {
        Dismount-DiskImage -ImagePath $WSVHDPath -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
        $MountedDisk = Mount-DiskImage -ImagePath $WSVHDPath -StorageType VHDX -ErrorAction SilentlyContinue

        If ( $($MountedDisk.Attached) -eq $true ) {
            $DriveLetter = $(Get-DiskImage -ImagePath $WSVHDPath | Get-Disk | Get-Partition | Get-Volume).DriveLetter

            if ($DriveLetter.Count -gt 1) { $DriveLetter = $DriveLetter[0] }
            $MaxSize = (Get-PartitionSupportedSize -DriveLetter $DriveLetter -ErrorAction SilentlyContinue).sizeMax

            #TODO: Make sure not the same size as the drives included in LabConfig
            Switch ($MaxSize) {
                {$_ -lt 100GB} {
                    Dismount-DiskImage -ImagePath $WSVHDPath -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
                    Resize-VHD -Path $WSVHDPath -SizeBytes (100GB)

                    #Note: Redo all this stuff in case the drive letters changed
                    $MountedDisk = Mount-DiskImage -ImagePath $WSVHDPath -StorageType VHDX -ErrorAction SilentlyContinue
                    $DriveLetter = $(Get-DiskImage -ImagePath $WSVHDPath | Get-Disk | Get-Partition | Get-Volume).DriveLetter

                    Resize-Partition -DriveLetter $DriveLetter -Size $MaxSize -ErrorAction SilentlyContinue
                }
            }

            Remove-Variable MaxSize -ErrorAction SilentlyContinue
            $MountPath = "$($DriveLetter):" -replace ' '


            If ( Test-Path "$MountPath\Windows\Panther\unattend.xml" ) {
                Write-Host "`t Unattend file exists..."
            }
            Else {
                Write-Host "`t Unattend file does not exist...Updating..."

                New-Item -Path "$MountPath\Windows\Panther" -ItemType Directory -Force | Out-Null
                Use-WindowsUnattend -Path $MountPath -UnattendPath $unattendfile -InformationAction SilentlyContinue

                'xActiveDirectory', 'xDNSServer', 'NetworkingDSC', 'xDHCPServer' | foreach-Object {
                    $thisModule = $_

                    Start-RSJob -Name "$thisModule-Modules" -ScriptBlock {
                        Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\$($using:thisModule)" -Destination "$($using:MountPath)\Program Files\WindowsPowerShell\Modules\" -Recurse -Force
                    } -OutVariable +RSJob | Out-Null
                }

                Wait-RSJob   $RSJob | Out-Null
                Remove-RSJob $RSJob | Out-Null

                Copy-Item -Path $unattendfile -Destination "$MountPath\Windows\Panther\unattend.xml" -Force
            }
        }
        Else { Write-Host "`t $WSVHDPath could not be mounted but was found (likely in use)" }
    }
    Else { Write-Error "$WSVHDPath was not found - Can't hydrate the basedisk" -ErrorAction Stop }

    Dismount-DiskImage -ImagePath $WSVHDPath -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
    Set-ItemProperty -Path $WSVHDPath -Name IsReadOnly -Value $true

    # Stuff needed for DCHydration
    $DN = @()
    $LabConfig.DomainName.Split(".") | ForEach-Object { $DN += "DC=$_," }
    $DN = $DN.TrimEnd(",")

    $DHCPscope = $LabConfig.DHCPscope
    $ReverseDNSrecord = $DHCPscope -replace '^(\d+)\.(\d+)\.\d+\.(\d+)$','$3.$2.$1.in-addr.arpa'
    $DHCPscope = $DHCPscope.Substring(0,$DHCPscope.Length-1)
    $DCIP = ($DHCPscope+'10/24')
    $GatewayIP = "$($LabConfig.DHCPscope.Substring(0,$LabConfig.DHCPscope.Length-1))1"

    #Create DSC configuration
    Configuration DCHydration {
        param (
            [Parameter(Mandatory)]
            [pscredential] $domainCred
        )

        # These must remain on separate lines per https://github.com/PowerShell/PSDscResources/issues/81
        # Error message received was "Exception calling "ImportClassResourcesFromModule" with "3" argument(s): "Resource name 'DnsRecordCname' is already being used by another Resource or Configuration.""
        Import-DscResource -ModuleName PSDesiredStateConfiguration
        Import-DscResource -ModuleName xActiveDirectory
        Import-DscResource -ModuleName xDNSServer
        Import-DscResource -ModuleName NetworkingDSC
        Import-DscResource -ModuleName xDHCPServer

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

            DefaultGatewayAddress DefaultGW {
                InterfaceAlias = 'Ethernet'
                AddressFamily = 'IPv4'
                Address = $GatewayIP
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
                LeaseDuration = '08:00:00'
                State         = 'Active'
                AddressFamily = 'IPv4'
                DependsOn = '[Service]DHCPServer'
            }

            DhcpServerOptionValue 'DefaultGW' {
                OptionId      = 3
                Value         = ($DHCPscope + '1')
                VendorClass   = ''
                UserClass     = ''
                AddressFamily = 'IPv4'
                Ensure        = 'Present'
                DependsOn = '[Service]DHCPServer'
            }

            DhcpScopeOptionValue 'DNSServers' {
                OptionId = 6
                Value = ($DHCPscope + '10')
                ScopeId =   ($DHCPscope + '0')
                VendorClass = ''
                UserClass   = ''
                AddressFamily = 'IPv4'
                DependsOn = '[Service]DHCPServer'
            }

            # Setting scope DNS domain name
            DhcpScopeOptionValue DNSDomainName {
                OptionId = 15
                Value = $Node.DomainName
                ScopeId =   ($DHCPscope + '0')
                VendorClass = ''
                UserClass   = ''
                AddressFamily = 'IPv4'
                DependsOn = '[Service]DHCPServer'
            }

            xDhcpServerAuthorization LocalServerActivation {
                Ensure = 'Present'
                IsSingleInstance = 'Yes'
            }

            xDnsServerADZone addReverseADZone {
                Name = $ReverseDNSrecord
                DynamicUpdate = "Secure"
                ReplicationScope = "Forest"
                Ensure = "Present"
                DependsOn = "[DhcpServerOptionValue]DefaultGW"
            }

            $localDNSServers = (Get-NetIPConfiguration | Where-Object IPv4DefaultGateway -ne $Null | Select-Object -First 1).DNSServer.ServerAddresses

            #Replace
            xDnsServerForwarder "forwarder_" {
                IsSingleInstance = 'Yes'
                IPAddresses = $localDNSServers
                UseRootHint = $true
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
                ActionAfterReboot  = 'ContinueConfiguration'
                ConfigurationMode  = 'ApplyAndAutoCorrect'
            }
        }
    }

    #create DSC MOF files
    Write-Host "`t Creating Domain Controller configuration"
    LCMConfig   -OutputPath "$VMPath\buildData\config" -ConfigurationData $ConfigData -InformationAction SilentlyContinue | Out-Null
    DCHydration -OutputPath "$VMPath\buildData\config" -ConfigurationData $ConfigData -domainCred $localCred -InformationAction SilentlyContinue | Out-Null

    If (-not (test-path "$VMPath\buildData\config\localhost.meta.mof")) { Write-Error 'Domain Controller LCM MOF creation failed' }
    If (-not (test-path "$VMPath\buildData\config\localhost.mof"))      { Write-Error 'Domain Controller Config MOF creation failed' }
}
#endregion

#region VMs and Host Hyper-V Configuration
Function Add-LabVirtualMachines {
    $Switchname   = $LabConfig.SwitchName
    $SwitchExists = (Get-VMSwitch -Name "$($LabConfig.Prefix)-$($LabConfig.Switchname)*" -ErrorAction SilentlyContinue)

    if (-not ($SwitchExists)) {
        $SwitchGuid = $(((New-Guid).Guid).Substring(0,10))
        $SwitchName = "$($LabConfig.Prefix)-$($LabConfig.Switchname)_$SwitchGuid"

        Write-Host "`t Creating switch $Switchname"
        $VMSwitch = New-VMSwitch -SwitchType Internal -Name $Switchname

        Rename-NetAdapter -Name "*$($LabConfig.Prefix)-$($LabConfig.Switchname)*" -NewName "NATGW-$($LabConfig.Prefix)-$($LabConfig.Switchname)"

        #TODO: This doesn't work if this is already in use, OR if we've already deployed another environment on this node
        $GatewayIP = "$($LabConfig.DHCPscope.Substring(0,$LabConfig.DHCPscope.Length-1))1"
        New-NetIPAddress -IPAddress $GatewayIP -PrefixLength 24 -InterfaceAlias "NATGW-$($LabConfig.Prefix)-$($LabConfig.Switchname)" | Out-Null
    }

    # If existing NAT is named wrong, delete then readd; else create the NAT
    $ExistingNat = Get-NetNat | Where-Object InternalIPInterfaceAddressPrefix -like "$($LabConfig.DHCPScope)*"

    If ($ExistingNat.Name -ne "Nat-$($LabConfig.Prefix)-$($LabConfig.Switchname)") {
        Get-NetNat | Where InternalIPInterfaceAddressPrefix -like "$($LabConfig.DHCPScope)*" | Remove-NetNat -Confirm:$false | Out-Null
        New-NetNat -Name "NAT-$($LabConfig.Prefix)-$($LabConfig.Switchname)" -InternalIPInterfaceAddressPrefix ($LabConfig.DHCPscope + "/24") | Out-Null
    }

    $LabConfig.VMs | ForEach-Object {
        $thisVM = $_
        $VM = Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue

        If ($VM) { Write-Host "`t VM named $($LabConfig.Prefix)$($_.VMName) already exists" }
        else {
            Write-Host "`t Creating VM: $($LabConfig.Prefix)$($_.VMName)"
            $VM = New-VM -Name "$($LabConfig.Prefix)$($_.VMName)" -MemoryStartupBytes $_.MemoryStartupBytes -Path $VMPath -SwitchName "$($LabConfig.Prefix)-$($LabConfig.Switchname)*" -Generation 2

            if ( $thisVM.Role -eq 'AzureStackHCI' ) {
                New-VHD -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ParentPath $HCIVHDPath -Differencing | Out-Null
            }
            else {
                New-VHD -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ParentPath $WSVHDPath -Differencing | Out-Null
            }

            $BootDevice = Add-VMHardDiskDrive -VMName "$($LabConfig.Prefix)$($_.VMName)" -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -Passthru -ErrorAction SilentlyContinue
            Set-VMFirmware -VMName "$($LabConfig.Prefix)$($_.VMName)" -BootOrder $BootDevice

            if ( $thisVM.Role -eq 'AzureStackHCI' ) {
                Set-VHD -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ParentPath $HCIVHDPath -IgnoreIdMismatch -ErrorAction SilentlyContinue
            }
            else {
                Set-VHD -Path "$($VM.Path)\Virtual Hard Disks\OSD.VHDX" -ParentPath $WSVHDPath -IgnoreIdMismatch -ErrorAction SilentlyContinue
            }
        }

        Set-VMSecurity  -VMName "$($LabConfig.Prefix)$($_.VMName)" -VirtualizationBasedSecurityOptOut $true
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
#endregion

#region Domain Creation
Function Assert-LabDomain {
    $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' } | Foreach-Object { $DCName = "$($LabConfig.Prefix)$($_.VMName)" }

    # Use local cred
    Invoke-Command -VMName $DCName -Credential $localCred -ScriptBlock {
        Set-DscLocalConfigurationManager -Path "$($using:GuestPath)\buildData\config" -Force | Out-Null
        Start-DscConfiguration           -Path "$($using:GuestPath)\buildData\config" -Force | Out-Null
    }
}

Function Wait-ForAzureStackHCIDomain {
    #TODO: Remove duplicate declaration; Also in Assert-LabDomain
    $LabConfig.VMs.Where{ $_.Role -eq 'Domain Controller' } | Foreach-Object {
        $DCName = "$($LabConfig.Prefix)$($_.VMName)"
    }

    $RebootCounter = 0
    do {
        # Use local cred until domain is created
        $DscConfigurationStatus = Invoke-Command -VMName $DCName -ScriptBlock {
            Get-DscConfigurationStatus -ErrorAction SilentlyContinue
        } -Credential $localCred -ErrorAction SilentlyContinue

        $DSCLocalConfigurationManager = Invoke-Command -VMName $DCName -ScriptBlock {
            Get-DSCLocalConfigurationManager -ErrorAction SilentlyContinue
        } -Credential $localCred -ErrorAction SilentlyContinue

        if ($DscConfigurationStatus.Status -ne 'Success') {
            Write-Host "`t Domain Controller Configuration in Progress. Sleeping for 10 seconds."

            If ($DSCLocalConfigurationManager.LCMState -eq $null) { Write-Host "`t `t LCM State : Unknown - Machine may be rebooting `n" }
            Else {
                Write-Host "`t `t LCM State : $($DSCLocalConfigurationManager.LCMState)"
                Write-Host "`t `t LCM Detail: $($DSCLocalConfigurationManager.LCMStateDetail) `n"

                If ($($DSCLocalConfigurationManager.LCMState) -eq 'PendingConfiguration') { $RebootCounter ++ }

                If ($RebootCounter -eq 6) {
                    Stop-VM  -VMName $DCName -Force
                    Start-VM -VMName $DCName

                    $RebootCounter = 0
                }
            }

            Start-Sleep 10
        } ElseIf ($DscConfigurationStatus.status -eq "Success" -and $DscConfigurationStatus.Type -ne 'LocalConfigurationManager' ) {
            Write-Host "`t Current Domain state: $($DscConfigurationStatus.status), ResourcesNotInDesiredState: $($DscConfigurationStatus.resourcesNotInDesiredState.count), ResourcesInDesiredState: $($DscConfigurationStatus.resourcesInDesiredState.count)"
        }
    } until ($DscConfigurationStatus.Status -eq 'Success' -and $DscConfigurationStatus.rebootrequested -eq $false)

    Remove-Variable RebootCounter -ErrorAction SilentlyContinue

    Write-Host "`t `t Domain $($LabConfig.DomainName) configured successfully `n"

    $DHCPScope = $LabConfig.DHCPscope

    # Use domain cred
    Invoke-Command -VMName $DCName -Credential $VMCred -ErrorAction SilentlyContinue -ScriptBlock {
        # Add reverse lookup zone (as setting reverse lookup does not work with DSC)
        Add-DnsServerPrimaryZone -NetworkID ($Using:DHCPscope + "/24") -ReplicationScope "Forest"

        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12' -Name ConfigurationState -Value 2
    }
}
#endregion

#region VM Hardware customization
Function Remove-AzureStackHCIVMHardware {
    # Cleanup; Remove existing drives (except OS); Remove existing NICs (except OS)

    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Start-RSJob -Name "$($thisVM.Name)-VMHardware Cleanup" -ScriptBlock {
            $thisJobVM = $using:thisVM

            [Console]::WriteLine("`t Removing old drives from: $($thisJobVM.Name)")
            Get-VMScsiController -VMName $thisJobVM.Name | ForEach-Object {
                $thisSCSIController = $_
                $thisSCSIController.Drives | ForEach-Object {
                    $thisVMDrive = $_

                    if (-not ($thisVMDrive.ControllerNumber -eq 0 -and $thisVMDrive.ControllerLocation -eq 0)) { $thisVMDrive | Remove-VMHardDiskDrive }
                }

                if ($thisSCSIController.ControllerNumber -ne 0) {
                    [Console]::WriteLine("`t `t Removing old SCSI controllers for: $($thisJobVM.Name)")
                    Remove-VMScsiController -VMName $thisJobVM.Name -ControllerNumber $thisSCSIController.ControllerNumber
                }
            }

            Remove-Item -Path (Join-Path -Path $thisJobVM.Path -ChildPath "Virtual Hard Disks\DataDisks") -Recurse -Force

            [Console]::WriteLine("`t Removing virtual adapters from: $($thisJobVM.Name)")
            Get-VMNetworkAdapter -VMName $thisJobVM.Name | ForEach-Object { Remove-VMNetworkAdapter -VMName $thisJobVM.Name }
        } -OutVariable +RSJob | Out-Null
    }

    # Make sure all previous jobs have completed
    Wait-RSJob   $RSJob | Out-Null
    Remove-RSJob $RSJob | Out-Null
}

# Create and attach new drives; then adapters
Function New-AzureStackHCIVMS2DDisks {
    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        #Note: This does not remove existing VMHardware. To remove/destroy (disks) first run Remove-AzureStackHCIVMS2DDisks
        Start-RSJob -Name "$($thisVM.Name)-CreateAndAttachDisks" -ScriptBlock {
            $thisJobVM = $using:thisVM

            #Note: After Lab Environment is deployed, there should be 1 SCSI controller for the OSD.
            #      This step will add 3 more. If this gets messed up re-run lab environment setup.
            [Console]::WriteLine("`t Creating SCSI Controllers for $($thisJobVM.Name)")
            1..3 | Foreach-Object { Add-VMScsiController -VMName $thisJobVM.Name -ErrorAction SilentlyContinue }

            $SCMPath = New-Item -Path (Join-Path $thisJobVM.Path 'DataDisks\SCM') -ItemType Directory -Force
            $SSDPath = New-Item -Path (Join-Path $thisJobVM.Path 'DataDisks\SSD') -ItemType Directory -Force
            $HDDPath = New-Item -Path (Join-Path $thisJobVM.Path 'DataDisks\HDD') -ItemType Directory -Force

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
        } -OutVariable +RSJob | Out-Null
    }
}

Function New-AzureStackHCIVMAdapters {
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
        } -OutVariable +RSJob | Out-Null
    }
}

Function Set-AzureStackHCIVMAdapters {
    # Rename Adapters inside guest
    $AzureStackHCIVMs | ForEach-Object {
        $thisVM = $_

        Write-Host "`t Renaming NICs in $($thisVM.Name) based on the vmNIC name for easy ID"
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
}

Function Register-AzureStackHCIStartupTasks {
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.HyperV.PowerShell.VirtualMachine[]] $VMs
    )

    $VMs | ForEach-Object {
        $thisVM = $_
        [Console]::WriteLine("`t Registering startup tasks on $($thisVM.Name)")

        New-Item "$VMPath\buildData\logon\$($thisVM.Name)-logon.ps1" -type File -Force -OutVariable startupScript | Out-Null

        # This section needs to be dynamically generated for each system because drives may be different.
        # Also want rename to run each time if needed
        $startupContent =  @"
            # Get the virtual machine name from the parent partition; Replace any non-alphanumeric characters with an underscore; trim to 15 characters
            `$vmName = (Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").VirtualMachineName
            `$vmName = [Regex]::Replace(`$vmName,"\W","_")
            `$vmName = `$vmName.Substring(0,[System.Math]::Min(15, `$vmName.Length))
            if (`$env:computername -ne `$vmName) { Rename-Computer -NewName `$vmName -ErrorAction SilentlyContinue}

            # Modify BCD to reduce recovery "help". We want the systems to start as fast as possible if they can. if they can't well just destroy and recreate.
            bcdedit /ems off
            bcdedit /set recoveryenabled no
            bcdedit /timeout 1

            # Prevent dirty shutdown notification
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name "DirtyShutdown"
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" -Name "DirtyShutdownTime"

            # Stop Server Manager from opening
            New-ItemProperty -Path HKLM:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value '0x1' -Force | Out-Null
"@

        Set-Content -Path $startupScript -value $startupContent

        if ( $LabConfig.VMs.Where{ "$($LabConfig.Prefix)$($_.VMName)" -eq $thisVM.Name }.Role -eq 'AzureStackHCI' ) {
            #Note: Due to issue with Set-PhysicalDisk, mediatype/name is reset after a reboot
            #      so we create a scheduled task to run inside the VM at startup; this will also work once S2D is enabled.
            $theseSCMDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.SCMDrives.Size
            $theseSSDDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.SSDDrives.Size
            $theseHDDDrivesSize = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.HDDDrives.Size

            # Disk objectIDs can change. Before clustering, they will be based on the computername.
            # After clustering, they'll be based on the cluster name, so including both
            $diskContent = @"
                try {
                    `$ClusterName = (Get-Cluster -ErrorAction SilentlyContinue).Name
                }
                catch { }


                if (`$ClusterName) {
                    Get-PhysicalDisk | Where-Object ObjectID -Match `$(`$ClusterName) | Where-Object Size -eq $theseSCMDrivesSize | Sort-Object Number | ForEach-Object {
                        Set-PhysicalDisk -UniqueId `$_.UniqueID -NewFriendlyName "`$(`$env:COMPUTERNAME)-PMEM`$(`$_.DeviceID)" -MediaType SCM
                    }

                    Get-PhysicalDisk | Where-Object ObjectID -Match `$(`$ClusterName) | Where-Object Size -eq $theseSSDDrivesSize | Sort-Object Number | ForEach-Object {
                        Set-PhysicalDisk -UniqueId `$_.UniqueID -NewFriendlyName  "`$(`$env:COMPUTERNAME)-SSD`$(`$_.DeviceID)" -MediaType SSD
                    }`

                    Get-PhysicalDisk | Where-Object ObjectID -Match `$(`$ClusterName) | Where-Object Size -eq $theseHDDDrivesSize | Sort-Object Number | ForEach-Object {
                        Set-PhysicalDisk -UniqueId `$_.UniqueID -NewFriendlyName  "`$(`$env:COMPUTERNAME)-HDD`$(`$_.DeviceID)" -MediaType HDD
                    }
                }
                Else {
                    Get-PhysicalDisk | Where-Object ObjectID -Match `$(`$env:COMPUTERNAME) | Where-Object Size -eq $theseSCMDrivesSize | Sort-Object Number | ForEach-Object {
                        Set-PhysicalDisk -UniqueId `$_.UniqueID -NewFriendlyName "`$(`$env:COMPUTERNAME)-PMEM`$(`$_.DeviceID)" -MediaType SCM
                    }

                    Get-PhysicalDisk | Where-Object ObjectID -Match `$(`$env:COMPUTERNAME) | Where-Object Size -eq $theseSSDDrivesSize | Sort-Object Number | ForEach-Object {
                        Set-PhysicalDisk -UniqueId `$_.UniqueID -NewFriendlyName  "`$(`$env:COMPUTERNAME)-SSD`$(`$_.DeviceID)" -MediaType SSD
                    }`

                    Get-PhysicalDisk | Where-Object ObjectID -Match `$(`$env:COMPUTERNAME) | Where-Object Size -eq $theseHDDDrivesSize | Sort-Object Number | ForEach-Object {
                        Set-PhysicalDisk -UniqueId `$_.UniqueID -NewFriendlyName  "`$(`$env:COMPUTERNAME)-HDD`$(`$_.DeviceID)" -MediaType HDD
                    }
                }
"@
            Add-Content -Path $startupScript -value $diskContent
        }

            $PathCheck = $startupScript.FullName -split ':'

            if (($PathCheck)[0] -ne 'C')
            {
                $DestinationPath = -join ('C:', $PathCheck[1])
            }
            else { $DestinationPath = $startupScript.FullName }

            Remove-Variable PathCheck -ErrorAction SilentlyContinue

        Copy-VMFile -Name $thisVM.Name -SourcePath $startupScript.FullName -DestinationPath $DestinationPath -CreateFullPath -FileSource Host -Force
        Invoke-Command -VMName $thisVM.Name -Credential $localCred -ScriptBlock {
            $thisJobVM = $($using:thisVM.Name)

            $Action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NonInteractive -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$($using:startupScript.FullName)`""
            $Trigger   = New-ScheduledTaskTrigger -AtStartup
            $Settings  = New-ScheduledTaskSettingsSet
            $principal = New-ScheduledTaskPrincipal -LogonType S4U -UserId SYSTEM -RunLevel Highest
            $Task      = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings

            Register-ScheduledTask -TaskName 'Azure Stack HCI Startup settings' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
            Start-ScheduledTask -TaskName 'Azure Stack HCI Startup settings'

            while ((Get-ScheduledTask -TaskName 'Azure Stack HCI Startup settings').State  -ne 'Ready') {
                [Console]::WriteLine("`t Waiting on first run of startup scheduled task for: $($thisJobVM)")
            }
        }
    }
}
#endregion
