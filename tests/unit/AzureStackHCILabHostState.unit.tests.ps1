Describe 'Host Validation' -Tags Host {
    Context HostOS {
        $NodeOS = Get-CimInstance -ClassName 'Win32_OperatingSystem'

        ### Verify the Host is sufficient version
        #TODO: Can this run on windows 10? - Not without WindowsFeature checking
        It "${env:ComputerName} must be Windows Server 2016, or Server 2019" {
            $NodeOS.Caption | Should be ($NodeOS.Caption -like '*Windows Server 2016*' -or $NodeOS.Caption -like '*Windows Server 2019*' )
        }

        # Not Implemented until everything gets to the PowerShell Gallery
        $RequiredModules = (Get-Module -Name AzureStackHCIJumpstart).RequiredModules
        $RequiredModules.GetEnumerator() | ForEach-Object {
            $thisModule = $_

            Remove-Variable module -ErrorAction SilentlyContinue
            $module = Get-Module $thisModule.Name -ListAvailable -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1

            It "[TestHost: ${env:ComputerName}] Must have the module [$($thisModule.Name)] available" {
                $module.Name | Should Not BeNullOrEmpty
            }

            It "[TestHost: ${env:ComputerName}] Must be at least version [$($thisModule.Version)]" {
                $module.version -ge $_.ModuleVersion | Should be $true
            }
        }

        $HyperVInstallationState = (Get-WindowsFeature | Where-Object Name -like *Hyper-V* -ErrorAction SilentlyContinue)

        $HyperVInstallationState | ForEach-Object {
            It "${env:ComputerName} must have $($_.Name) installed" {
                $_.InstallState | Should be 'Installed'
            }
        }

        It "${env:ComputerName} must have the specified ISO from LabConfig.ServerISOFolder" {
            Test-Path $LabConfig.ServerISOFolder | Should be $true
        }
    }
}
