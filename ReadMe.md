[![Build status](https://ci.appveyor.com/api/projects/status/0u9f8smiidg1j4kn/branch/master?svg=true)](https://ci.appveyor.com/project/PowerShell/xcertificate/branch/master)

# xCertificate
The **xCertificate** module is a part of the Windows PowerShell Desired State Configuration (DSC) Resource Kit, which is a collection of DSC Resources. This module includes DSC resources that simplify administration of certificates on a Windows Server, with simple declarative language.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

Installation
------------

To install **xCertificate** module

-   If you are using WMF4 / PowerShell Version 4: Unzip the content under the C:\Program Files\WindowsPowerShell\Modules folder

-   If you are using WMF5 Preview: From an elevated PowerShell session run "Install-Module xCertificate"

To confirm installation

-   Run Get-DSCResource to see that the resources listed above are among the DSC Resources displayed

## Contributing
Please check out common DSC Resources [contributing guidelines](https://github.com/PowerShell/DscResource.Kit/blob/master/CONTRIBUTING.md).

Resources
-------

**xCertReq** resource has following properties

- **Subject**: Provide the text string to use as the subject of the certificate
- **CAServerFQDN**: The FQDN of the Active Directory Certificate Authority on the local area network
- **CARootName**: The name of the certificate authority, by default this will be in format domain-servername-ca
- **Credential**: The credentials that will be used to access the template in the Certificate Authority
- **AutoRenew**: Determines if the resource will also renew a certificate within 7 days of expiration

**xPfxImport** resource has following properties

- **Thumbprint**: The thumbprint (unique identifier) of the certificate you're importing.
- **Path**: The path to the PFX file you want to import.
- **Location**: 'LocalMachine' or 'CurrentUser
- **Store**: Defaults to `My` (the personal store) but can be any store that is valid on the machine (for example, `WebHosting`).
- **Exportable**: Defaults to `$false`. Determines whether the private key is exportable from the machine after you import it.
- **Credential**: A `[PSCredential]` object that is used to decrypt the PFX file. Only the password is used, so any user name is valid.
- **Ensure**: Present or Absent; Specifies whether the certificate should be present or absent.

**xCertificateImport** resource has following properties

- **Thumbprint**: The thumbprint (unique identifier) of the certificate you're importing.
- **Path**: The path to the CER file you want to import.
- **Location**: 'LocalMachine' or 'CurrentUser
- **Store**: Defaults to `My` (the personal store) but can be any store that is valid on the machine (for example, `WebHosting`).
- **Ensure**: Present or Absent; Specifies whether the certificate should be present or absent.

## Versions

### Unreleased
* Converted appveyor.yml to install Pester from PSGallery instead of from Chocolatey.

### 2.1.0.0
* Fixed xCertReq to support CA Root Name with spaces

### 2.0.0.0
* Breaking Change - Updated xPfxImport Store parameter is now a key value making it mandatory
* Updated xPfxImport with new Ensure support
* Updated xPfxImport with support for the CurrentUser value
* Updated xPfxImport with validationset for the Store parameter
* Added new resource: xCertificateImport

### 1.1.0.0
* Added new resource: xPfxImport

### 1.0.1.0

* Minor documentation updates

### 1.0.0.0

* Initial public release of xCertificate module with following resources
	* xCertReq

Examples
--------

## xCertReq

**Example 1**:  Request and Accept a certificate from an Active Directory Root Certificate Authority.

```powershell
configuration SSL
{
    param (
        [Parameter(Mandatory=$true)] 
        [ValidateNotNullorEmpty()] 
        [PsCredential] $Credential 
        )
    Import-DscResource -ModuleName xCertificate
    Node 'localhost'
    {
        xCertReq SSLCert
        {
            CARootName                = 'test-dc01-ca'
            CAServerFQDN              = 'dc01.test.pha'
            Subject                   = 'foodomain.test.net'
            AutoRenew                 = $true
            Credential                = $Credential
        }
    }
}
$configData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost';
            PSDscAllowPlainTextPassword = $true
        }
    )
}
SSL -ConfigurationData $configData -Credential (get-credential) -OutputPath 'c:\SSLConfig'
Start-DscConfiguration -Wait -Force -Verbose -Path 'c:\SSLConfig'

# Validate results
Get-ChildItem Cert:\LocalMachine\My
```

## xPfxImport

### Simple Usage

```powershell
xPfxImport CompanyCert
{
    Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
    Path = '\\Server\Share\Certificates\CompanyCert.pfx'
    Credential = $PfxPassword
}
```

### Used with xWebAdministration Resources

```powershell
xPfxImport CompanyCert
{
    Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
    Path = '\\Server\Share\Certificates\CompanyCert.pfx'
    Store = 'WebHosting'
    Credential = $PfxPassword
    DependsOn = '[WindowsFeature]IIS'
}
```

## xCertificateImport

**Example 1**: Import public key certificate into Trusted Root store 

```powershell
xCertificateImport MyTrustedRoot
{
    Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
    Store = 'Root'
    Path = '\\Server\Share\Certificates\MyTrustedRoot.cer'
}
```
