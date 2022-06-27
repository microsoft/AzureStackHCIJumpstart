[![Build status](https://ci.appveyor.com/api/projects/status/y6682ir5f5nj28in?svg=true)](https://ci.appveyor.com/project/MSFTCoreNet/AzureStackHCIJumpstart)
[![downloads](https://img.shields.io/powershellgallery/dt/AzureStackHCIJumpstart.svg?label=downloads)](https://www.powershellgallery.com/packages/AzureStackHCIJumpstart)

# Jumpstart your Azure Stack HCI Lab

This module is intended to deploy a **lab environment** for testing Azure Stack HCI - specifically using the deployment UI in Windows Admin Center. With this module, you can test your Azure Stack HCI deployment in VMs, on a single host, and **emulate** various configurations including:

- NIC configurations (emulate Intel, Marvel, Mellanox, Chelsio, Broadcom, etc.)
- Disk types (SCM, SSD, HDD)

There are several unique configurations that makes testing the deployment UI in VMs challenging. This module simplifies (requires only one input) these challenges as it was purpose-built.

For more details on what this does, please see [What it does in a little more depth](#What-it-does-in-a-little-more-depth)

## Installation

Install this module from the PowerShell Gallery using ```Install-Module AzureStackHCIJumpstart```

or for disconnected systems: ```Save-Module -Name AzureStackHCIJumpstart -Path c:\somefolderpath```

## What's New - Version 2020.1.1.3

Minor update to allow you to specify the BaseVHDX or ServerISO property at runtime (instead of in the config file). E.g. you can set these params in the config file or:

```powershell
    Initialize-AzureStackHCILabOrchestration -BaseVHDX 'c:\SomeFolder\Base.VHDX'
```

```powershell
    Initialize-AzureStackHCILabOrchestration -ServerISO 'c:\SomeFolder\Server.ISO'
```

Specifying at runtime will overwrite the value in the Get-AzureStackHCILabConfig.

## What's New - Version 2020.1.1.2

The latest version added:

- You can now rerun the `Initialize-AzureStackHCILabOrchestration` repeatedly on the nodes. This is useful if one or more of the VMs are messed up, disks, or NICs, Active Directory, etc., are messed up

- You can now provide a VHDX or an ISO to create VMs. VHDX greatly speeds up the lab deployment time as hyrdration from an ISO is one of the longest tasks.

- Parallelized several tasks that apply to all VMs or the Azure Stack HCI VMs

- Checkpoints that let you accelerate and revert the deployment phases for quick practice *(Stages 0 (start) - 4 (S2D))*. To use the snapshots use ```New-AzureStackHCIStageSnapshot``` or ```Restore-AzureStackHCIStageSnapshot``` or ```Remove-AzureStackHCIStageSnapshot``` (Syntax is shown below).

- Internet access from the VMs

# Getting Started

## Getting this module to your system

Until published on the PowerShell gallery, use ```git clone``` to clone the repo to a local folder. If not cloned to an auto-searched PowerShell location, run ```Import-Module <Path to AzureStackHCIJumpstart.psd1> -Force```

Once this module is in the PowerShell gallery, use ```Install-Module AzureStackHCIJumpstart``` or for air-gapped systems [Save-Module](https://docs.microsoft.com/en-us/powershell/module/powershellget/save-module). If using ```Save-Module``` you'll need to specify a folder to save the module and all dependencies, then move the module to the disconnected system. Make sure to place the module in one of the auto-searched folders, e.g. ```C:\Program Files\WindowsPowerShell\Modules\...```

## Required Configuration

By default, you must provide a ISO or a VHDX which will be used to install VMs. You need to provide only one these and update that **one** value to create the lab. To do this follow one of the following methods:

### Option 1: Specify at runtime

```powershell
    Initialize-AzureStackHCILabOrchestration -BaseVHDX 'c:\SomeFolder\Base.VHDX'
```

```powershell
    Initialize-AzureStackHCILabOrchestration -ServerISO 'c:\SomeFolder\Server.ISO'
```

### Option 2: Specify in Get-AzureStackHCILabConfig

1. Open **.\AzureStackHCIJumpstart\AzureStackHCIJumpstart.psm1**

2. In the `Get-AzureStackHCILabConfig` function, edit either the `ServerISO` or the `BaseVHDX` property.

    a. The other property should be commented out with a `#`

        1. `ServerISO` This is the path to a Windows ISO file used to create the base (parent) disk

        2. `BaseVHDX` This is a VHDX with a Windows OS image installed

    b. You can experiment using existing VMs rather than having the lab create them however you still need to provide either the `ServerISO` or the `BaseVHDX` file path. Instructions for using your own VMs are out of scope.

    **Note: If you make changes to the module, you must re-import before the changes will be realized. Use: ipmo .\AzureStackHCIJumpstart.psd1 -Force

3. Run `Initialize-AzureStackHCILabOrchestration`

## Additional (but not required) configuration (e.g. you don't have to do this)

1. Open **.\AzureStackHCIJumpstart\AzureStackHCIJumpstart.psm1**

2. In the `Get-AzureStackHCILabConfig` function, edit the desired properties

### Example 1: Change the file location where VMs, basedisk, etc. will be stored

Old:

```PowerShell
    $global:VMPath = 'C:\DataStore\VMs'
```

New:

```PowerShell
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

# Deployment

> Note: This module is designed to be run multiple times. If you run into an issue, file a bug and rerun the lab orchestration.

## Deploy the lab

```PowerShell
    Initialize-AzureStackHCILabOrchestration
```

## Snapshot stages of the lab

You can use the snapshot commands to "fast-forward" your lab to a particular stage. You can use this for example if you don't want to worry about testing Stages 1 (feature installation), 2 (Networking) or 3 (Clustering), but do want to test stage 4 (S2D), and Stage 5 (SDN).

Following the deployment of the lab, use the following commands to take snapshots of the lab. This command supports snapshots for stage 0 (fresh install) through stage 4

```PowerShell
    New-AzureStackHCIStageSnapshot -Stage 0
```

```PowerShell
    New-AzureStackHCIStageSnapshot -Stage 1
```

...etc...

## Restore the lab to a stage

While you can restore the snapshots manually, this ensures that all machines are on the correct snapshot with one command (potentially including the domain controller)

```PowerShell
    Restore-AzureStackHCIStageSnapshot -Stage 0
```

```PowerShell
    Restore-AzureStackHCIStageSnapshot -Stage 1
```

## Remove the lab
=======
Note: The long-term goal is that these two commands can all be run independently but additional testing is needed. If you find an issue, file a bug and just keep running the lab orchestration command

```New-AzureStackHCILabEnvironment```

```Invoke-AzureStackHCILabVMCustomization```

## Destruction

**Removes all HCI VMs (Hyper-V Hosts)**

```PowerShell
    Remove-AzureStackHCILabEnvironment
```

**Additionally removes the domain controller, virtual switch, NAT configuration, and base disk**

```PowerShell
    Remove-AzureStackHCILabEnvironment -FireAndBrimstone
```

## Troubleshooting

**After the lab orchestration command completes, I see a red-error "Credential Invalid"**

This indicates we were unable to log into one of the VMs and perform some work. To resolve this, try running the ```Initialize-AzureStackHCILabOrchestration``` again.

If it continues and this wasn't the first time deploying the VMs (e.g. the VMs (including WAC and the DC) already existed when you ran ```Initialize-AzureStackHCILabOrchestration```), please try removing the VMs with the command ```Remove-AzureStackHCILabEnvironment -FireAndBrimstone``` then recreating the lab.

If this continues to happen, please file an issue on GitHub.

# What it does in a little more depth

> ### Subtitle: Why does it take so long?

It's doing a lot and there are some long-running tasks (measured in minutes rather than seconds). Here's a quick look at the overall process:

> Note: Several of these tasks are parallelized so output on screen may appear out of order.
> Note: Any steps that have already been completed are skipped on subsequent runs of the module.

- Run prerequisite checks on the host

- {long} Create a new base disk. This is the parent disk initially used by the VMs and uses a basic unattend file. This is only necessary if you specify the ```ServerISO``` property

- Creates an internal virtual switch and a NAT network for the VMs to attach to

- Create any missing VMs

    - Rename VMs guest OS to match the name in Hyper-V and (once domain is created) join the VMs to the domain

    - Removes old VMHardware (NICs and Disks) then recreates them. Ensures everything is clean and predictable/identical inside the VMs.

    - Enables inbound SMB and ICMP firewall rules.

- {long} Make copies of the base disk for each VM. Once copies are complete, reparent the VHDX to the copy. This serves two purposes:

    - Allows for immediate startup of virtual machines.
    - Improves VM performance once reparented

- {long} Create the AD Domain; configures DHCP used to program the rest of the VMs; configures DNS to resolve internet-based resources.

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
