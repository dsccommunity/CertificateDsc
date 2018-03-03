<#
    .EXAMPLE
    Exports a certificate as a CERT using the friendly name to identify it.
#>
Configuration Example
{
    param
    (
        [Parameter()]
        [System.String[]]
        $NodeName = 'localhost'
    )

    Import-DscResource -ModuleName CertificateDsc

    Node $AllNodes.NodeName
    {
        CertificateExport SSLCert
        {
            Type         = 'CERT'
            FriendlyName = 'Web Site SSL Certificate for www.contoso.com'
            Path         = 'c:\sslcert.cer'
        }
    }
}
