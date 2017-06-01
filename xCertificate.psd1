@{
    # Version number of this module.
    ModuleVersion = '2.6.0.0'

    # ID used to uniquely identify this module
    GUID = '1b8d785e-79ae-4d95-ae58-b2460aec1031'

    # Author of this module
    Author = 'Microsoft Corporation'

    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright = '(c) 2015 Microsoft Corporation. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'This module includes DSC resources that simplify administration of certificates on a Windows Server'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '4.0'

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = '4.0'

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module
    FunctionsToExport = '*'

    # Cmdlets to export from this module
    CmdletsToExport = '*'

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('DesiredStateConfiguration', 'DSC', 'DSCResourceKit', 'DSCResource')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/PowerShell/xCertificate/blob/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/PowerShell/xCertificate'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
        ReleaseNotes = '- Added mandatory properties for xPfxImport resource example.
- xCertReq:
  - Fixed issue where xCertReq does not identify when DNS Names in SANs are incorrect.
  - Added Certificate Authority auto-discovery to resource xCertReq.
  - Added SAN and certificate template name to xCertReq"s Get-TargetResource
  - Added new parameter UseMachineContext to be able to use CA templates that try to fill the subject alternative name
- CertificateDSc.Common:
  - Added function Get-CertificateTemplateName to retrieve template name
  - Added function Get-CertificateSan to retrieve subject alternative name
  - Added function Find-CertificateAuthority to enable auto-discovery

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}






