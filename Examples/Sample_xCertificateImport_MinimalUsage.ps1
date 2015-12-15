Configuration MyNode
{
    Import-DscResource -ModuleName xCertificate

    Node $AllNodes.NodeName
    {
        xCertificateImport MyTrustedRoot
        {
            Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Store = "Root"
            Path = '\\Server\Share\Certificates\MyTrustedRoot.cer'
        }
    }
}