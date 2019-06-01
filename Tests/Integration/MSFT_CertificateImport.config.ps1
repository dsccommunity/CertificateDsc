Configuration MSFT_CertificateImport_Config {
    Import-DscResource -ModuleName CertificateDsc

    node localhost {
        CertificateImport Integration_Test {
            Thumbprint   = $Node.Thumbprint
            Path         = $Node.Path
            Location     = $Node.Location
            Store        = $Node.Store
            Ensure       = $Node.Ensure
            FriendlyName = $Node.FriendlyName
        }
    }
}
