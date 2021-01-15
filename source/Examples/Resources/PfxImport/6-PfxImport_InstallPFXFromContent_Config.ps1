<#PSScriptInfo
.VERSION 1.0.0
.GUID fa81342d-b96d-401b-8a18-c96bebd4aff6
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

#Requires -Modules CertificateDsc

<#
    .DESCRIPTION
        Import a PFX into the 'My' Local Machine certificate store.
#>
Configuration PfxImport_InstallPFXFromContent_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName CertificateDsc

    <#
        .DESCRIPTION
            Create mock base64 value
            example for converting an existing file:
            $contentBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($certificateFilePath))
    #>
    $contentBase64 = [System.Convert]::ToBase64String(@(00, 00, 00))

    Node localhost
    {
        PfxImport CompanyCert
        {
            Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Content    = $contentBase64
            Location   = 'LocalMachine'
            Store      = 'My'
            Credential = $Credential
        }
    }
}
