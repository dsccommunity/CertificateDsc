Configuration MyNode
{
    param(
        [PSCredential]
        $PfxPassword = (Get-Credential -Message 'Enter PFX extraction password.' -UserName 'Ignore')
    )

    Import-DscResource -ModuleName xCertificate

    Node $AllNodes.NodeName
    {
        xPfxImport CompanyCert
        {
            Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Path = '\\Server\Share\Certificates\CompanyCert.pfx'
            Credential = $PfxPassword
        }
    }
}