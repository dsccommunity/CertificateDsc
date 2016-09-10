# Import a PFX into the My store.
Configuration Sample_xPfxImport_MinimalUsage
{
    param
    (
        [PSCredential]
        $PfxPassword = (Get-Credential -Message 'Enter PFX extraction password.' -UserName 'Ignore')
    )

    Import-DscResource -ModuleName xCertificate

    Node $AllNodes.NodeName
    {
        xPfxImport CompanyCert
        {
            Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Path       = '\\Server\Share\Certificates\CompanyCert.pfx'
            Credential = $PfxPassword
        }
    }
}
Sample_xPfxImport_MinimalUsage `
    -OutputPath 'c:\Sample_xPfxImport_MinimalUsage'
Start-DscConfiguration -Wait -Force -Verbose -Path 'c:\Sample_xPfxImport_MinimalUsage'

# Validate results
Get-ChildItem Cert:\LocalMachine\My
