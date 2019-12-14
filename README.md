# Jumpstart your Azure Stack HCI Lab

This module is intended to deploy a lab environment for testing Azure Stack HCI. It should be run from a Hyper-V host.

This module can:

- Check that the

## Customizing the deployment

By default you only need to update one value to run this

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
