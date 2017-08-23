@{
    # Version number of this module.
    ModuleVersion = '3.0.0.0'

    # ID used to uniquely identify this module
    GUID              = '1b8d785e-79ae-4d95-ae58-b2460aec1031'

    # Author of this module
    Author            = 'Microsoft Corporation'

    # Company or vendor of this module
    CompanyName       = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright         = '(c) 2017 Microsoft Corporation. All rights reserved.'

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
            LicenseUri   = 'https://github.com/PowerShell/xCertificate/blob/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/PowerShell/xCertificate'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
        ReleaseNotes = '- Add CodeCov.io code coverage reporting.
- Opted into "Common Tests - Validate Example Files".
- Fixed bugs in examples.
- Updated License and Manifest Copyright info to be 2017 Microsoft Corporation.
- xCertReq:
  - BREAKING CHANGE: Changed default Keylength to 2048 bits to meet
    [Microsoft Security Advisory](https://support.microsoft.com/en-us/help/2661254/microsoft-security-advisory-update-for-minimum-certificate-key-length).
  - Fixed spelling mistakes in MOF files.
- Added .github support files:
  - CONTRIBUTING.md
  - ISSUE_TEMPLATE.md
  - PULL_REQUEST_TEMPLATE.md
- Opted into Common Tests "Validate Module Files" and "Validate Script Files".
- Converted files with UTF8 with BOM over to UTF8 - fixes [Issue 87](https://github.com/PowerShell/xCertificate/issues/87).
- Converted to use auto-documentation/wiki format - fixes [Issue 84](https://github.com/PowerShell/xCertificate/issues/84).

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}









