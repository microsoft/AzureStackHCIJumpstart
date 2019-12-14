Describe 'Lab Validation' -Tags Lab {
    Context VMs {
        $LabConfig.VMs.Where{$_.Role -eq 'AzureStackHCI'} | ForEach-Object {
            $VMName = "$($LabConfig.Prefix)$($_.VMName)"

            It "Should have the VM: $VMName" {
                Get-VM -VMName $VMName -ErrorAction SilentlyContinue | Should BeOfType 'Microsoft.HyperV.PowerShell.VirtualMachine'
            }
        }
    }

    $AzureStackHCIVMs = @()
    $LabConfig.VMs.Where{$_.Role -eq 'AzureStackHCI'} | ForEach-Object {
        $AzureStackHCIVMs += Get-VM -VMName "$($LabConfig.Prefix)$($_.VMName)" -ErrorAction SilentlyContinue
    }

    <#Context Disks {
        $AzureStackHCIVMs | Foreach-Object {
            $thisVM = $_

            Context "$($thisVM.Name)-Disks" {
                $theseAdapters = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.Adapters
                $actualVMAdapters = (Get-VMNetworkAdapter -VMName $thisVM.Name)

                It "Should have $($theseAdapters.Count) adapters" {
                    $actualVMAdapters.Count -eq $theseAdapters.Count | Should be $true
                }
            }
        }
    }#>

    $AzureStackHCIVMs | Foreach-Object {
        $thisVM = $_

        Context "$($thisVM.Name)-NICs" {
            $theseAdapters = $LabConfig.VMs.Where{$thisVM.Name -like "*$($_.VMName)"}.Adapters
            $actualVMAdapters = (Get-VMNetworkAdapter -VMName $thisVM.Name)

            It "Should have $($theseAdapters.Count) adapters" {
                $actualVMAdapters.Count -eq $theseAdapters.Count | Should be $true
            }
        }
    }
        #TODO: Test for correct disks
        #TODO: Test for correct size of disks
}
