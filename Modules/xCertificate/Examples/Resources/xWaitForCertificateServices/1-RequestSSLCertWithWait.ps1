<#
    .EXAMPLE
    Request and Accept a certificate from an Active Directory Root Certificate Authority.
    The CA may not be initially available (e.g. it may still be being installed) so
    the config will first wait for it to become available.

    This example is allowing storage of credentials in plain text by setting
    PSDscAllowPlainTextPassword to $true.
    Storing passwords in plain text is not a good practice and is presented only for
    simplicity and demonstration purposes.
    To learn how to securely store credentials through the use of certificates,
    please refer to the following TechNet topic:
    https://technet.microsoft.com/en-us/library/dn781430.aspx
#>
configuration Example
{
    param
    (
        [Parameter()]
        [System.String[]]
        $NodeName = 'localhost',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName xCertificate

    Node $AllNodes.NodeName
    {
        xWaitForCertificateServices RootCA
        {
            CARootName   = 'test-dc01-ca'
            CAServerFQDN = 'dc01.test.pha'
        }

        xCertReq SSLCert
        {
            CARootName          = 'test-dc01-ca'
            CAServerFQDN        = 'dc01.test.pha'
            Subject             = 'foodomain.test.net'
            KeyLength           = '2048'
            Exportable          = $true
            ProviderName        = '"Microsoft RSA SChannel Cryptographic Provider"'
            OID                 = '1.3.6.1.5.5.7.3.1'
            KeyUsage            = '0xa0'
            CertificateTemplate = 'WebServer'
            AutoRenew           = $true
            FriendlyName        = 'SSL Cert for Web Server'
            Credential          = $Credential
            DependsOn           = '[xWaitForCertificateServices]RootCA'
        }
    }
}
