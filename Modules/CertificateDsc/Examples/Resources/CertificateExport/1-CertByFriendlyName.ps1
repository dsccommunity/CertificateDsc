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

    Import-DscResource -ModuleName xCertificate

    Node $AllNodes.NodeName
    {
        xCertificateExport SSLCert
        {
            Type         = 'CERT'
            FriendlyName = 'Web Site SSL Certificate for www.contoso.com'
            Path         = 'c:\sslcert.cer'
        }
    }
}
