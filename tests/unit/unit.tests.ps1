Describe 'Host Validation' -Tags Host {
    Context HostOS {
        $NodeOS = Get-CimInstance -ClassName 'Win32_OperatingSystem'

        ### Verify the Host is sufficient version
        #TODO: Can this run on windows 10?
        It "${env:ComputerName} must be Windows Server 2016, or Server 2019" {
            $NodeOS.Caption | Should be ($NodeOS.Caption -like '*Windows Server 2016*' -or $NodeOS.Caption -like '*Windows Server 2019*' )
        }

        $HyperVInstallationState = (Get-WindowsFeature | Where Name -like *Hyper-V* -ErrorAction SilentlyContinue)

        $HyperVInstallationState | ForEach-Object {
            It "${env:ComputerName} must have $($_.Name) installed" {
                $_.InstallState | Should be 'Installed'
            }
        }
    }
}
