<#PSScriptInfo
.VERSION 1.0.0
.GUID 30f2fb68-3199-424e-9783-393486c7885b
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT
.TAGS DSCConfiguration
.LICENSEURI https://github.com/PowerShell/CertificateDsc/blob/master/LICENSE
.PROJECTURI https://github.com/PowerShell/CertificateDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module CertificateDsc

<#
    .DESCRIPTION
        Import public key certificate into Trusted Root store.
#>
Configuration CertificateImport_MinimalUsage_Config
{
    Import-DscResource -ModuleName CertificateDsc

    Node localhost
    {
        CertificateImport MyTrustedRoot
        {
            Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Location   = 'LocalMachine'
            Store      = 'Root'
            Path       = '\\Server\Share\Certificates\MyTrustedRoot.cer'
        }
    }
}
