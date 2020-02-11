Describe "$($env:repoName)-Manifest" {
    $DataFile   = Import-PowerShellDataFile .\$($env:repoName).psd1 -ErrorAction SilentlyContinue
    $TestModule = Test-ModuleManifest       .\$($env:repoName).psd1 -ErrorAction SilentlyContinue

    Context Manifest-Validation {
        It "[Import-PowerShellDataFile] - $($env:repoName).psd1 is a valid PowerShell Data File" {
            $DataFile | Should Not BeNullOrEmpty
        }

        It "[Test-ModuleManifest] - $($env:repoName).psd1 should not be empty" {
            $TestModule | Should Not BeNullOrEmpty
        }
    }

    Context "Required Modules" {
        'Pester' | ForEach-Object {
            $module = Find-Module -Name $_ -ErrorAction SilentlyContinue

            It "Should contain the $_ Module" {
                $_ -in ($TestModule).RequiredModules.Name | Should be $true
            }

            It "The $_ module should be available in the PowerShell gallery" {
                $module | Should not BeNullOrEmpty
            }
        }
    }

    Context ExportedContent {
        $testCommand = Get-Command Convert-LBFO2SET

        It 'Should have the BaseVHDX param' {
            Get-Command Initialize-AzureStackHCILabOrchestration | Should -HaveParameter BaseVHDX -Not -Mandatory
        }

        It 'Should have the ServerISO param' {
            Get-Command Initialize-AzureStackHCILabOrchestration | Should -HaveParameter ServerISO -Not -Mandatory
        }

        Import-Module .\$($env:repoName).psd1 -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

        'Get-AzureStackHCILabConfig',
        'Remove-AzureStackHCILabEnvironment',
        'New-AzureStackHCIStageSnapshot',
        'Restore-AzureStackHCIStageSnapshot',
        'Remove-AzureStackHCIStageSnapshot',
        'Initialize-AzureStackHCILabOrchestration' | ForEach-Object {
            It "Should have the $($env:repoName) function available" {
                $_ | Should not BeNullOrEmpty
            }
        }
    }
}
