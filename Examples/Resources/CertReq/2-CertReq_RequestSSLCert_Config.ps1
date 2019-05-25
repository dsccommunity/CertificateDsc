<#PSScriptInfo
.VERSION 1.0.0
.GUID 02814aa7-53b2-49a0-ad4e-904f1f05664c
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
        Request and Accept a certificate from an Active Directory Root Certificate Authority.

        This example is allowing storage of credentials in plain text by setting PSDscAllowPlainTextPassword to $true.
        Storing passwords in plain text is not a good practice and is presented only for simplicity and demonstration purposes.
        To learn how to securely store credentials through the use of certificates,
        please refer to the following TechNet topic: https://technet.microsoft.com/en-us/library/dn781430.aspx
#>
configuration CertReq_RequestSSLCert_Config
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName CertificateDsc

    Node localhost
    {
        CertReq SSLCert
        {
            CARootName          = 'test-dc01-ca'
            CAServerFQDN        = 'dc01.test.pha'
            Subject             = 'foodomain.test.net'
            KeyLength           = '2048'
            Exportable          = $true
            ProviderName        = 'Microsoft RSA SChannel Cryptographic Provider'
            OID                 = '1.3.6.1.5.5.7.3.1'
            KeyUsage            = '0xa0'
            CertificateTemplate = 'WebServer'
            AutoRenew           = $true
            FriendlyName        = 'SSL Cert for Web Server'
            Credential          = $Credential
            KeyType             = 'RSA'
            RequestType         = 'CMC'
        }
    }
}
