# CertificateDsc

[![Build Status](https://dev.azure.com/dsccommunity/CertificateDsc/_apis/build/status/dsccommunity.CertificateDsc?branchName=master)](https://dev.azure.com/dsccommunity/CertificateDsc/_build/latest?definitionId=28&branchName=master)
![Code Coverage](https://img.shields.io/azure-devops/coverage/dsccommunity/CertificateDsc/28/master)
[![Azure DevOps tests](https://img.shields.io/azure-devops/tests/dsccommunity/CertificateDsc/28/master)](https://dsccommunity.visualstudio.com/CertificateDsc/_test/analytics?definitionId=28&contextType=build)
[![PowerShell Gallery (with prereleases)](https://img.shields.io/powershellgallery/vpre/CertificateDsc?label=CertificateDsc%20Preview)](https://www.powershellgallery.com/packages/CertificateDsc/)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/CertificateDsc?label=CertificateDsc)](https://www.powershellgallery.com/packages/CertificateDsc/)

## Code of Conduct

This project has adopted [this code of conduct](CODE_OF_CONDUCT.md).

## Releases

For each merge to the branch `master` a preview release will be
deployed to [PowerShell Gallery](https://www.powershellgallery.com/).
Periodically a release version tag will be pushed which will deploy a
full release to [PowerShell Gallery](https://www.powershellgallery.com/).

## Contributing

Please check out common DSC Community [contributing guidelines](https://dsccommunity.org/guidelines/contributing).

## Change log

A full list of changes in each version can be found in the [change log](CHANGELOG.md).

## Resources

The **CertificateDsc** module is a part of the Windows PowerShell Desired State
Configuration (DSC) Resource Kit, which is a collection of DSC Resources. This
module includes DSC resources that simplify administration of certificates on a
Windows Server, with simple declarative language.

The **CertificateDsc** module contains the following resources:

- **CertificateExport**: Used to export a certificate from a Windows certificate
  store.
- **CertificateImport**: Used to import a certificate into a Windows certificate
  store.
- **CertReq**: Used to request a new certificate from an certificate authority.
- **PfxImport**: Used to import a PFX certificate into a Windows certificate store.
- **WaitForCertificateServices**: Used to wait for a Active Directory Certificate
  Services Certificate Authority to become available.

This project has adopted [this code of conduct](CODE_OF_CONDUCT.md).

## Documentation and Examples

For a full list of resources in CertificateDsc and examples on their use, check out
the [CertificateDsc wiki](https://github.com/dsccommunity/CertificateDsc/wiki).
