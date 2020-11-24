<#PSScriptInfo
.VERSION 1.0.0
.GUID 48a20a89-efc4-4ea7-8da5-e9f740aa89fe
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT Copyright the DSC Community contributors. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/dsccommunity/CertificateDsc/blob/master/LICENSE
.PROJECTURI https://github.com/dsccommunity/CertificateDsc
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
        Create mock base64 value
    example for converting an existing file:
    $contentBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($certificateFilePath))
#>
$contentBase64 = [System.Convert]::ToBase64String(@(00, 00, 00))

<#
    .DESCRIPTION
        Import public key certificate into Trusted Root store from
        a provided base64 encoded string.
#>
Configuration CertificateImport_WithContent_Config
{
    Import-DscResource -ModuleName CertificateDsc

    Node localhost
    {
        CertificateImport MyTrustedRoot
        {
            Thumbprint   = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Location     = 'LocalMachine'
            Store        = 'Root'
            Path         = 'C:\Windows\Temp\MyTrustedRoot.cer'
            Content      = $contentBase64
        }
    }
}
