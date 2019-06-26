@{
    # Version number of this module.
    moduleVersion = '4.7.0.0'

    # ID used to uniquely identify this module
    GUID              = '1b8d785e-79ae-4d95-ae58-b2460aec1031'

    # Author of this module
    Author            = 'Microsoft Corporation'

    # Company or vendor of this module
    CompanyName       = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright         = '(c) 2018 Microsoft Corporation. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'This module includes DSC resources that simplify administration of certificates on a Windows Server'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '4.0'

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion        = '4.0'

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module
    FunctionsToExport = '*'

    # Cmdlets to export from this module
    CmdletsToExport   = '*'

    # DSC resources to export from this module
    DscResourcesToExport = @('CertificateExport','CertificateImport','CertReq','PfxImport','WaitForCertificateServices')

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('DesiredStateConfiguration', 'DSC', 'DSCResourceKit', 'DSCResource')

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/PowerShell/CertificateDsc/blob/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/PowerShell/CertificateDsc'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
        ReleaseNotes = '- Opted into Common Tests "Common Tests - Validate Localization" -
  fixes [Issue 195](https://github.com/PowerShell/CertificateDsc/issues/195).
- Combined all `CertificateDsc.ResourceHelper` module functions into
  `CertificateDsc.Common` module and renamed to `CertificateDsc.CommonHelper`
  module.
- CertReq:
  - Fix error when ProviderName parameter is not encapsulated in
    double quotes - fixes [Issue 185](https://github.com/PowerShell/CertificateDsc/issues/185).
- Refactor integration tests to update to latest standards.
- Refactor unit tests to update to latest standards.
- CertificateImport:
  - Refactor to use common functions and share more code with `PfxImport`
    resource.
  - Resource will now only throw an exception if the PFX file does not exist
    and it needs to be imported.
  - Removed file existence check from `Path` parameter to enable the resource
    to remove a certificate from the store without the need to have the
    access to the certificate file.
  - Removed ShouldProcess because it is not required by DSC Resources.
- CertificatePfx:
  - Refactor to use common functions and share more code with
    `CertificateImport` resource.
  - Resource will now only throw an exception if the certificate file does
    not exist and it needs to be imported.
- CertificateImport:
  - Added `FriendlyName` parameter to allow setting the certificate friendly
    name of the imported certificate - fixes [Issue 194](https://github.com/PowerShell/CertificateDsc/issues/194).
- CertificatePfx:
  - Added `FriendlyName` parameter to allow setting the certificate friendly
    name of the imported certificate - fixes [Issue 194](https://github.com/PowerShell/CertificateDsc/issues/194).

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}



















