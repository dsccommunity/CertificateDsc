# CertificateDsc

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
the [CertificateDsc wiki](https://github.com/PowerShell/CertificateDsc/wiki).

## Branches

### master

[![Build status](https://ci.appveyor.com/api/projects/status/0u9f8smiidg1j4kn/branch/master?svg=true)](https://ci.appveyor.com/project/PowerShell/CertificateDsc/branch/master)
[![codecov](https://codecov.io/gh/PowerShell/CertificateDsc/branch/master/graph/badge.svg)](https://codecov.io/gh/PowerShell/CertificateDsc/branch/master)

This is the branch containing the latest release - no contributions should be made
directly to this branch.

### dev

[![Build status](https://ci.appveyor.com/api/projects/status/0u9f8smiidg1j4kn/branch/dev?svg=true)](https://ci.appveyor.com/project/PowerShell/CertificateDsc/branch/dev)
[![codecov](https://codecov.io/gh/PowerShell/CertificateDsc/branch/dev/graph/badge.svg)](https://codecov.io/gh/PowerShell/CertificateDsc/branch/dev)

This is the development branch to which contributions should be proposed by contributors
as pull requests. This development branch will periodically be merged to the master
branch, and be released to [PowerShell Gallery](https://www.powershellgallery.com/).

## Contributing

Please check out common DSC Resources [contributing guidelines](https://github.com/PowerShell/DscResource.Kit/blob/master/CONTRIBUTING.md).
