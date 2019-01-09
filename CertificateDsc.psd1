@{
    # Version number of this module.
    moduleVersion = '4.2.0.0'

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
        ReleaseNotes = '- Added a CODE_OF_CONDUCT.md with the same content as in the README.md - fixes
  [Issue 139](https://github.com/PowerShell/CertificateDsc/issues/139).
- Refactored module folder structure to move resource to root folder of
  repository and remove test harness - fixes [Issue 142](https://github.com/PowerShell/CertificateDsc/issues/142).
- Updated Examples to support deployment to PowerShell Gallery scripts.
- Correct configuration names in Examples - fixes [Issue 150](https://github.com/PowerShell/CertificateDsc/issues/150).
- Correct filename case of `CertificateDsc.Common.psm1` - fixes [Issue 149](https://github.com/PowerShell/CertificateDsc/issues/149).
- Remove exclusion of all tags in appveyor.yml, so all common tests can be run
  if opt-in.
- PfxImport:
  - Added requirements to README.MD to specify cryptographic algorithm
    support - fixes [Issue 153](https://github.com/PowerShell/CertificateDsc/issues/153).
  - Changed Path parameter to be optional to fix error when ensuring certificate
    is absent and certificate file does not exist on disk - fixes [Issue 136](https://github.com/PowerShell/CertificateDsc/issues/136).
  - Removed ShouldProcess because it is not required by DSC Resources.
  - Minor style corrections.
  - Changed unit tests to be non-destructive.
  - Improved naming and description of example files.
  - Added localization string ID suffix for all strings.
- Added .VSCode settings for applying DSC PSSA rules - fixes [Issue 157](https://github.com/PowerShell/CertificateDsc/issues/157).

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}














