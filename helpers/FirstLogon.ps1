# Get the virtual machine name from the parent partition
$vmName = (Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").VirtualMachineName

# Replace any non-alphanumeric characters with an underscore
$vmName = [Regex]::Replace($vmName,"\W","_")

# Trim names that are longer than 15 characters
$vmName = $vmName.Substring(0,[System.Math]::Min(15, $vmName.Length))

# Check the trimmed and cleaned VM name against the guest OS name
# If it is different, change the guest OS name and reboot
if ($env:computername -ne $vmName) { Rename-Computer -NewName $vmName}

# Modify BCD
bcdedit /ems off
bcdedit /set recoveryenabled no
bcdedit /timeout 1
