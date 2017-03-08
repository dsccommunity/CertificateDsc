<#
    .EXAMPLE
    Import a PFX into the My store.
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
        xPfxImport CompanyCert
        {
            Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Path       = '\\Server\Share\Certificates\CompanyCert.pfx'
            Credential = $Credential
        }
    }
}
