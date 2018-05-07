Configuration MSFT_PfxImport_Add_Config {
    param
    (
        $Thumbprint,
        $Path,
        $Credential
    )
    Import-DscResource -ModuleName CertificateDsc
    node localhost {
        PfxImport Integration_Test {
            Thumbprint   = $Thumbprint
            Path         = $Path
            Location     = 'LocalMachine'
            Store        = 'My'
            Ensure       = 'Present'
            Credential   = $Credential
        }
    }
}
