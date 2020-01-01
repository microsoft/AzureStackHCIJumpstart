# Jumpstart your Azure Stack HCI Lab

This module is intended to deploy a lab environment for testing Azure Stack HCI - specifically using the deployment UI in Windows Admin Center. With this module, you can test the Azure Stack HCI deployment in various configurations:

- Various NIC configurations
- Various disk types (SCM, SSD, HDD)

For more details on what this does, please see [What it does in a little more depth](#What it does in a little more depth)


## What's New - 12/31/19

In the latest updates we have added:

- Parallelization for several tasks that applied to all VMs or the Azure Stack HCI VMs

- Checkpoints that let you accelerate the deployment phases (Currently stage 1 and 3 only)

- Internet access from the VMs
    - Uses an internal vSwitch on the host to provide a NAT (https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/setup-nat-network) to the VMs.
    The internal domain

- Resolved issues where the disk media types were reset following a reboot

- Moved exported functions to the main module; removed non-exported functions to the helpers module. You should now only call functions located in the AzureStackHCIJumpstart module


# Customizing the deployment

By default you only need to update one value to run this

..\helpers\helpers.psm1 - Edit the path to the ISO file. This is the ISO used for installing all the VMs. (you can use existing VMs rather than create your own. But you still need to give a path to an ISO file)

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

> ## Subtitle: Why does it take so long?

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
