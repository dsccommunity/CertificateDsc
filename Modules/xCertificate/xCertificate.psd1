@{
    # Version number of this module.
    ModuleVersion = '3.1.0.0'

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
        ReleaseNotes = '- xCertReq:
  - Fixed behaviour to allow certificate templates with spaces in the name
- Added `Documentation and Examples` section to Readme.md file - see
  [issue 98](https://github.com/PowerShell/xCertificate/issues/98).
- Changed description in Credential parameter of xPfxImport resource
  to correctly generate parameter documentation in Wiki - see [Issue 103](https://github.com/PowerShell/xCertificate/issues/103).
- Changed description in Credential parameter of xCertReq resource
  to clarify that a PSCredential object should be used.
- Updated tests to meet Pester V4 guidelines - fixes [Issue 105](https://github.com/PowerShell/xCertificate/issues/105).
- Add support for Windows Server 2008 R2 which does not contain PKI
  module so is missing `Import-PfxCertificate` and `Import-Certificate`
  cmdlets - fixes [Issue 46](https://github.com/PowerShell/xCertificate/issues/46).

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}










