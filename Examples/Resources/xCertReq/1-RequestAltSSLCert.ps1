<#
    .EXAMPLE
    Request and Accept a certificate from an Active Directory Root Certificate Authority. This certificate
    is issued using an subject alternate name with multiple DNS addresses.

    This example is allowing storage of credentials in plain text by setting PSDscAllowPlainTextPassword to $true.
    Storing passwords in plain text is not a good practice and is presented only for simplicity and demonstration purposes.
    To learn how to securely store credentials through the use of certificates,
    please refer to the following TechNet topic: https://technet.microsoft.com/en-us/library/dn781430.aspx
#>
configuration Example
{
    param
    (
        [Parameter()]
        [string[]]
        $NodeName = 'localhost',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName xCertificate
    Node 'localhost'
    {
        xCertReq SSLCert
        {
            CARootName                = 'test-dc01-ca'
            CAServerFQDN              = 'dc01.test.pha'
            Subject                   = 'contoso.com'
            KeyLength                 = '1024'
            Exportable                = $true
            ProviderName              = '"Microsoft RSA SChannel Cryptographic Provider"'
            OID                       = '1.3.6.1.5.5.7.3.1'
            KeyUsage                  = '0xa0'
            CertificateTemplate       = 'WebServer'
            SubjectAltName            = 'dns=fabrikam.com&dns=contoso.com'
            AutoRenew                 = $true
            Credential                = $Credential
        }
    }
}
