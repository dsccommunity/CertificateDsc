Configuration MSFT_PfxImport_Add_Config {
    Import-DscResource -ModuleName CertificateDsc

    node localhost {
        PfxImport Integration_Test {
            Thumbprint   = $Node.Thumbprint
            Path         = $Node.Path
            Location     = $Node.Location
            Store        = $Node.Store
            Ensure       = $Node.Ensure
            Credential   = $Node.Credential
            FriendlyName = $Node.FriendlyName
        }
    }
}

Configuration MSFT_PfxImport_Remove_Config {
    Import-DscResource -ModuleName CertificateDsc

    node localhost {
        PfxImport Integration_Test {
            Thumbprint = $Node.Thumbprint
            Location   = $Node.Location
            Store      = $Node.Store
            Ensure     = $Node.Ensure
        }
    }
}
