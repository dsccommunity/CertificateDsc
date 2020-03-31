<#PSScriptInfo
.VERSION 1.0.0
.GUID 14b1346a-436a-4f64-af5c-b85119b819b3
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
        Exports a certificate as a CERT using the friendly name to identify it.
#>
Configuration CertificateExport_CertByFriendlyName_Config
{
    Import-DscResource -ModuleName CertificateDsc

    Node localhost
    {
        CertificateExport SSLCert
        {
            Type         = 'CERT'
            FriendlyName = 'Web Site SSL Certificate for www.contoso.com'
            Path         = 'c:\sslcert.cer'
        }
    }
}
