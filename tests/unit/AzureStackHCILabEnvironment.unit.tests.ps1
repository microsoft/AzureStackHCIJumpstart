Describe 'Lab Validation' -Tags Lab {
    Context VMs {
        $LabConfig.VMs.Where{$_.Role -eq 'AzureStackHCI'} | ForEach-Object {
            $VMName = "$($LabConfig.Prefix)$($_.VMName)"

            It "Should have the VM: $VMName" {
                Get-VM -VMName $VMName -ErrorAction SilentlyContinue | Should BeOfType 'Microsoft.HyperV.PowerShell.VirtualMachine'
            }
        }
    }
}
