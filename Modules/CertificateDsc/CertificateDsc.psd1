@{
    # Version number of this module.
    moduleVersion = '4.1.0.0'

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
        ReleaseNotes = '- PfxImport:
  - Changed so that PFX will be reimported if private key is not
    installed - fixes [Issue 129](https://github.com/PowerShell/CertificateDsc/issues/129).
  - Corrected to meet style guidelines.
  - Corrected path parameter description - fixes [Issue 125](https://github.com/PowerShell/CertificateDsc/issues/125).
  - Refactored to remove code duplication by creating Get-CertificateStorePath.
  - Improved unit tests to meet standards and provide better coverage.
  - Improved integration tests to meet standards and provide better coverage.
- CertificateDsc.Common:
  - Corrected to meet style guidelines.
  - Added function Get-CertificateStorePath for generating Certificate Store path.
  - Remove false verbose message from `Test-Thumbprint` - fixes [Issue 127](https://github.com/PowerShell/CertificateDsc/issues/127).
- CertReq:
  - Added detection for FIPS mode in Test-Thumbprint - fixes [Issue 107](https://github.com/PowerShell/CertificateDsc/issues/107).

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}













