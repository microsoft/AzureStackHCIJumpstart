Measure-Command {
    'AzStackHCI01', 'AzStackHCI02', 'AzStackHCI03', 'AzStackHCI04' | ForEach-Object {
        $thisVM = $_

        1..10 | Foreach-Object {
            New-VHD -Path "C:\Datastore\VMs\Tester\$thisVM-HDD-$_.VHDX" -Dynamic -SizeBytes 50GB #-ErrorAction SilentlyContinue -InformationAction SilentlyContinue
        }
    }
}

Measure-Command {
    $Servers = 'AzStackHCI01', 'AzStackHCI02', 'AzStackHCI03', 'AzStackHCI04'
    foreach ($server in $servers) {
        1..10 | start-rsjob -Name "$server-Disks" -ScriptBlock {
            $thisDisk = $_

            New-VHD -Path "C:\Datastore\VMs\Tester\$($using:server)-HDD-$thisDisk.VHDX" -Dynamic -SizeBytes 50GB #-ErrorAction SilentlyContinue -InformationAction SilentlyContinue
        }
    }

    Get-RSJob -Name "AzStackHCI01-Disks"  | Wait-RSJob
    Get-RSJob -Name "AzStackHCI02-Disks"  | Wait-RSJob
    Get-RSJob -Name "AzStackHCI03-Disks"  | Wait-RSJob
    Get-RSJob -Name "AzStackHCI04-Disks"  | Wait-RSJob

    Get-RSJob | Remove-RSJob
}

'xActiveDirectory', 'xDNSServer', 'NetworkingDSC', 'xDHCPServer', 'xPSDesiredStateConfiguration' | foreach-Object {
    $thisModule = $_
    start-rsjob -Name "$thisModule-Modules" -ScriptBlock {
        Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\$($using:thisModule)" -Destination "C:\Datastore\VMs\Tester\" -Recurse -Force
    }
}

Get-RSJob | Wait-RSJob -ShowProgress

$something = Get-RSJob | ? State -ne Completed

Get-RSJob | Remove-RSJob

Get-RSJob -Name "AzStackHCI02-Disks"  | Wait-RSJob
Get-RSJob -Name "AzStackHCI03-Disks"  | Wait-RSJob
Get-RSJob -Name "AzStackHCI04-Disks"  | Wait-RSJob


$AllVMs | Foreach-Object {
    $thisVM = $_

    start-rsjob -Name "$($thisVM.Name)-Reparent" -ScriptBlock {
        $VHDXToConvert = $using:thisVM | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0
        $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath

        if ($BaseDiskPath -eq $VHDPath) {
            Write-Host "Beginning VHDX Reparenting for $($_.Name)"
            Move-ToNewParentVHDX -VM $using:thisVM -VHDXToConvert $VHDXToConvert
        }
    }
}

Get-RSJob | Wait-RSJob
Get-RSJob | Remove-RSJob

$AllVMs | ForEach-Object {
    $thisVM = $_

    Start-RSJob -Name "$($thisVM.Name)-Reparent" -FunctionsToImport 'Move-ToNewParentVHDX' -ScriptBlock {
        $VHDXToConvert = $using:thisVM | Get-VMHardDiskDrive -ControllerLocation 0 -ControllerNumber 0
        $BaseDiskPath = (Get-VHD -Path $VHDXToConvert.Path).ParentPath

        if ($BaseDiskPath -eq $VHDPath) {
            Write-Host "Beginning VHDX Reparenting for $($_.Name)"
            Move-ToNewParentVHDX -VM $using:thisVM -VHDXToConvert $VHDXToConvert
        }
    }
}