@{
    # Version number of this module.
    moduleVersion = '4.4.0.0'

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
        ReleaseNotes = '- Minor style corrections from PR for
  [Issue 161](https://github.com/PowerShell/CertificateDsc/issues/161)
that were missed.
- Opt-in to Example publishing to PowerShell Gallery - fixes
  [Issue 177](https://github.com/PowerShell/CertificateDsc/issues/177).
- Changed Test-CertificateAuthority to return the template name if it finds the
  display name of the template in the certificate -fixes
  [Issue 147](https://github.com/PowerShell/CertificateDsc/issues/147).

'

        } # End of PSData hashtable

    } # End of PrivateData hashtable

}
















