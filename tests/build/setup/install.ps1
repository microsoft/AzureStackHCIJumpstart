git.exe clone -q https://github.com/PowerShell/DscResource.Tests

Import-Module -Name "$env:APPVEYOR_BUILD_FOLDER\DscResource.Tests\AppVeyor.psm1"
Invoke-AppveyorInstallTask

Remove-Item .\DscResource.Tests\ -Force -Confirm:$false -Recurse

# Add pester here if not included in the RequiredModules portion of the module manifest
#[string[]]$PowerShellModules = @('posh-git', 'psake', 'poshspec', 'PSScriptAnalyzer')

$ModuleManifest = Test-ModuleManifest .\$($env:RepoName).psd1 -ErrorAction SilentlyContinue
$repoRequiredModules = $ModuleManifest.RequiredModules.Name

If ($repoRequiredModules) { $PowerShellModules += $repoRequiredModules }

# This section is taken care of by Invoke-AppVeyorInstallTask
<#[string[]]$PackageProviders = @('NuGet', 'PowerShellGet')

# Install package providers for PowerShell Modules
ForEach ($Provider in $PackageProviders) {
    If (!(Get-PackageProvider $Provider -ErrorAction SilentlyContinue)) {
        Install-PackageProvider $Provider -Force -ForceBootstrap -Scope CurrentUser
    }
}#>

# Feature Installation

$serverFeatureList = @('Hyper-V')

If ($PowerShellModules -contains 'FailoverClusters') {
    $serverFeatureList += 'RSAT-Clustering-Mgmt', 'RSAT-Clustering-PowerShell'
}

$BuildSystem = Get-CimInstance -ClassName 'Win32_OperatingSystem'

ForEach ($Module in $PowerShellModules) {
    If ($Module -eq 'FailoverClusters') {
        Switch -Wildcard ($BuildSystem.Caption) {
            '*Windows 10*' {
                Write-Output 'Build System is Windows 10'
                Write-Output "Not Implemented"

                # Get FailoverCluster Capability Name and Install on W10 Builds
                $capabilityName = (Get-WindowsCapability -Online | Where-Object Name -like *RSAT*FailoverCluster.Management*).Name
                Add-WindowsCapability -Name $capabilityName -Online
            }

            Default {
                Write-Output "Build System is $($BuildSystem.Caption)"
                Install-WindowsFeature -Name $serverFeatureList -IncludeManagementTools | Out-Null
            }
        }
    }
    ElseIf ($Module -eq 'Pester') {
        Write-Output "Uninstalling Pester version >= 5.0"
        Get-Module -Name Pester -ListAvailable | ? Version -gt '5.0' | Uninstall-Module
        
        Write-Output "Installing Pester version 4.9.0"
        Install-Module $Module -Scope AllUsers -Force -Repository PSGallery -AllowClobber -SkipPublisherCheck -RequiredVersion 4.9.0
        Import-Module $Module -RequiredVersion 4.9.0
    }
    else {
        Install-Module $Module -Scope AllUsers -Force -Repository PSGallery -AllowClobber
        Import-Module $Module
        Get-Module $Module
    }

    Import-Module $Module
}
