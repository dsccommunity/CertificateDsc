Configuration MSFT_xCertificateExport_Config {
    Import-DscResource -ModuleName xCertificate
    node localhost {
        if ($Node.Type -in @('Cert','P7B','SST'))
        {
            xCertificateExport Integration_Test {
                Path             = $Node.Path
                FriendlyName     = $Node.FriendlyName
                Subject          = $Node.Subject
                DNSName          = $node.DNSName
                Issuer           = $Node.Issuer
                KeyUsage         = $Node.KeyUsage
                EnhancedKeyUsage = $Node.EnhancedKeyUsage
                Type             = $Node.Type
                MatchSource      = $Node.MatchSource
            }
        }
        elseif ($Node.Type -eq 'PFX')
        {
            xCertificateExport Integration_Test {
                Path             = $Node.Path
                FriendlyName     = $Node.FriendlyName
                Subject          = $Node.Subject
                DNSName          = $node.DNSName
                Issuer           = $Node.Issuer
                KeyUsage         = $Node.KeyUsage
                EnhancedKeyUsage = $Node.EnhancedKeyUsage
                Type             = $Node.Type
                MatchSource      = $Node.MatchSource
                ChainOption      = 'BuildChain'
                Password         = $Node.Password
            }
        }
    }
}
