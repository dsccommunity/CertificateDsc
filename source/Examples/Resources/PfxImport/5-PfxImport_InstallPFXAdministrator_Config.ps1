<#PSScriptInfo
.VERSION 1.0.0
.GUID dca596de-c24c-4600-bca8-9897d60c41c3
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
        Import a PFX into the 'Root' Local Machine certificate store using
        an administrator credential.
#>
Configuration PfxImport_InstallPFX_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $AdminCredential
    )

    Import-DscResource -ModuleName CertificateDsc

    Node localhost
    {
        PfxImport CompanyCert
        {
            Thumbprint           = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Path                 = '\\Server\Share\Certificates\CompanyCert.pfx'
            Location             = 'LocalMachine'
            Store                = 'Root'
            Credential           = $Credential
            PsDscRunAsCredential = $AdminCredential
        }
    }
}
