<#PSScriptInfo
.VERSION 1.0.0
.GUID f35aa0ac-1b22-4309-89aa-05618419e7b9
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
        Import public key certificate into Trusted Root store and
        set the Fiendly Name to 'Contoso Root CA'.
#>
Configuration CertificateImport_FriendlyName_Config
{
    Import-DscResource -ModuleName CertificateDsc

    Node localhost
    {
        CertificateImport MyTrustedRoot
        {
            Thumbprint   = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Location     = 'LocalMachine'
            Store        = 'Root'
            Path         = '\\Server\Share\Certificates\MyTrustedRoot.cer'
            FriendlyName = 'Contoso Root CA'
        }
    }
}
