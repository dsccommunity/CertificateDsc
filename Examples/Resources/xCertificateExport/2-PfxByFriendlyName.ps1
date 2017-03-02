<#
    .EXAMPLE
    Exports a certificate as a PFX using the friendly name to identify it.
#>
Configuration Example
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

    Node $AllNodes.NodeName
    {
        xCertificateExport SSLCert
        {
            Type         = 'PFX'
            FriendlyName = 'Web Site SSL Certificate for www.contoso.com'
            Path         = 'c:\sslcert.cer'
            Password     = $Credential
        }
    }
}
