@{
    # Version number of this module.
    ModuleVersion     = '2.8.0.0'

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
  - Added FriendlyName parameter to xCertReq.
  - Changed exceptions to be raised using New-InvalidOperationException from PSDscResources.
  - Changed integration tests to use Config Data instead of value in config to support
    additional tests.
  - Converted unit tests to use Get-InvalidOperationRecord in CommonTestHelper.
  - Improved unit test style to match standard layout.
  - Minor corrections to style to be HQRM compliant.
  - Improved Verbose logging by writing all lines of CertReq.exe output.
  - Fixed CA auto-detection to work when CA name contains a space.
- Corrected all makrdown rule violations in README.MD.
- Added markdownlint.json file to enable line length rule checking in VSCode
  with [MarkdownLint extension](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint)
  installed.
- Added the VS Code PowerShell extension formatting settings that cause PowerShell
  files to be formatted as per the DSC Resource kit style guidelines.
- Fixed verbose preference not being passed to CertificateDsc.Common functions -
  fixes [Issue 70](https://github.com/PowerShell/xCertificate/issues/70).
- Converted all calls to `New-InvalidArgumentError` function to `New-InvalidArgumentException`
  found in `CertificateDsc.ResourceHelper` - fixes [Issue 68](https://github.com/PowerShell/xCertificate/issues/68)
- Replaced all calls to `Write-Error` with calls to `New-InvalidArgumentException`
  and `New-InvalidOperationException`
- xWaitForCertificateServices:
  - Added new resource.
- Cleaned up example format to meet style guidelines and changed examples to
  issue 2048 bit certificates.
- Fixed spelling error in xCertificateExport Issuer parameter description.

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}








