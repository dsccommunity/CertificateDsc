@{
    # Version number of this module.
    moduleVersion = '4.0.0.0'

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
        ReleaseNotes = '- BREAKING CHANGE
  - Renamed xCertificate to CertificateDsc - fixes [Issue 114](https://github.com/PowerShell/xCertificate/issues/114).
  - Changed all MSFT_xResourceName to MSFT_ResourceName.
  - Updated DSCResources, Examples, Modules and Tests for new naming.
  - Updated Year to 2018 in License and Manifest.
  - Updated README.md from xCertificate to CertifcateDsc
  - Removed unnecessary code from:
    - CertificateDsc\Modules\CertificateDsc\DSCResources\MSFT_CertReq\MSFT_CertReq.psm1
      - Deleted $rspPath = [System.IO.Path]::ChangeExtension($workingPath, ".rsp")

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}












