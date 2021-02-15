Configuration DSC_CertificateImport_Config {
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

Configuration DSC_CertificateImport_Config_WithContent {
    Import-DscResource -ModuleName CertificateDsc

    node localhost {
        CertificateImport Integration_Test {
            Thumbprint   = $Node.Thumbprint
            Content      = $Node.Content
            Location     = $Node.Location
            Store        = $Node.Store
            Ensure       = $Node.Ensure
            FriendlyName = $Node.FriendlyName
        }
    }
}
