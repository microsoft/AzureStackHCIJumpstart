# Jumpstart your Azure Stack HCI Lab

This module is intended to deploy a ****lab environment*** for testing Azure Stack HCI - specifically using the deployment UI in Windows Admin Center. With this module, you can test your Azure Stack HCI deployment in VMs, on a single host, in various configurations including various:

- NIC configurations
- Disk types (SCM, SSD, HDD)

For more details on what this does, please see [What it does in a little more depth](#What-it-does-in-a-little-more-depth)

## What's New - Version 2020.1.1.2

The latest version added:

- Parallelization for several tasks that applied to all VMs or the Azure Stack HCI VMs

- Checkpoints that let you accelerate the deployment phases (Currently stage 0 and 1 only)

- Internet access from the VMs

- Resolved issues where the disk media types were reset following a reboot

- Moved functions that can be called by the user to the main module `\AzureStackHCIJumpstart.psm1`

- Moved functions used by the module (not directly by the user) to the helpers module.

# Getting Started

By default you must update **one** value to run the module.

1. Open ****.\AzureStackHCIJumpstart\AzureStackHCIJumpstart.psm1****

2. In the `Get-AzureStackHCILabConfig` function, edit the `ServerISOFolder` property

    a. This is the path to a Windows ISO file used to create the base (parent) disk

    b. You can use existing VMs rather than create your own however you still need to give a path to an ISO file. Instructions for using your own VMs are out of scope.

3. Run `Initialize-AzureStackHCILabOrchestration`

## Additional (but not required) configuration

1. Open ****.\AzureStackHCIJumpstart\AzureStackHCIJumpstart.psm1****

2. In the `Get-AzureStackHCILabConfig` function, edit the desired properties

### Example 1: Change the file location where VMs, basedisk, etc. will be stored

Old:

```powershell
    $global:VMPath = 'C:\DataStore\VMs'
```

New:

```powershell
    $global:VMPath = 'C:\SomeNewFolder\MyVMPath'
```

### Example 2: Change the domain name and password

Old:

```PowerShell
    DomainAdminName   = 'Bruce'
    AdminPassword     = 'd@rkKnight!'
    DomainName        = 'gotham.city'
```

New:

```PowerShell
    DomainAdminName   = 'Harley'
    AdminPassword     = 'h@rlequ1n'
    DomainName        = 'Arkham.Assylum'
```

### Example 3: Change the number of Azure Stack HCI VMs

Old:

```PowerShell
    1..4 | ForEach-Object {
        $LABConfig.VMs += @{
```

New:

```PowerShell
    1..2 | ForEach-Object {
        $LABConfig.VMs += @{
```

## Deployment

Note: The long-term goal is that these two commands can all be run independently but additional testing is needed. If you find an issue, file a bug and just keep running the lab orchestration command

```New-AzureStackHCILabEnvironment```

```Invoke-AzureStackHCILabVMCustomization```

### Deploy the entire lab with VM customization

```Initialize-AzureStackHCILabOrchestration```

### Just Deploy the lab infrastructure (don't customize VMs)

```New-AzureStackHCILabEnvironment```

### Customize the lab VMs; don't redeploy stuff

```Invoke-AzureStackHCILabVMCustomization```

## Destruction

**Removes all HCI VMs (Hyper-V Hosts and WAC VM)**

```Remove-AzureStackHCILabEnvironment```

**Additionally removes the domain controller, virtual switch, and base disk**

```Remove-AzureStackHCILabEnvironment -FireAndBrimstone```

# What it does in a little more depth

> ### Subtitle: Why does it take so long?

It's doing a lot and there are some long-running tasks (measured in minutes rather than seconds). Here's a quick look at the overall process:

> Note: Several of these tasks are parallelized so output on screen may appear out of order.
> Note: Any steps that have already been completed are skipped on subsequent runs of the module.

- Run prerequisite checks on the host

- {long} Create a new base disk. This is the parent disk initially used by the VMs and uses a basic unattend file.

- Creates an internal virtual switch and a NAT network for the VMs to attach to

- Create any missing VMs

    - Rename VMs guest OS to match the name in Hyper-V and (once domain is created) join the VMs to the domain
    - Removes old VMHardware (NICs and Disks) then recreates them. Ensures everything is clean and predictable/identical inside the VMs.
    - Enables inbound SMB and ICMP firewall rules.

- {long} Make copies of the base disk for each VM. Once copies are complete, reparent the VHDX to the copy. This serves two purposes:

    - Allows for immediate startup of virtual machines.
    - Improves VM performance once reparented

- {long} Create the AD Domain; configures DHCP used to program the rest of the VMs; configures DNS to resolve internet-based resources.

- {long} Creates VM Snapshots to allow you to test different stages more easily
    - Stage 0 - Includes anything needed before the deployment UI can start
    - Stage 1 - Windows features are installed on Azure Stack HCI VMs
    - Stage 2 (Net) - No snapshot currently taken
    - Stage 3       - #TODO: Update this section
    - Stage 4 (S2D) - No snapshot currently taken
    - Stage 5 (SDN) - No snapshot currently taken

# Community or external modules used

Special thanks to the owners/maintainers of these modules:

- Convert-WindowsImage (Microsoft Hyper-V Team)
- Pester
- PoshRSJob
- NetworkingDsc
- xActiveDirectory
- xDHCPServer
- xDNSServer

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
