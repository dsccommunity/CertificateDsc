#Requires -module CertificateDsc

<#
    .DESCRIPTION
        Exports a certificate as a CERT using the friendly name to identify it.
#>
Configuration Example
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
