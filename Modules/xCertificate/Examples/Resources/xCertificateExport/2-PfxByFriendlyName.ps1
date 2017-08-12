<#
    .EXAMPLE
    Exports a certificate as a PFX using the friendly name to identify it.
#>
Configuration Example
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
        xCertificateExport SSLCert
        {
            Type         = 'PFX'
            FriendlyName = 'Web Site SSL Certificate for www.contoso.com'
            Path         = 'c:\sslcert.cer'
            Password     = $Credential
        }
    }
}
