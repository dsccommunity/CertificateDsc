Configuration MSFT_PfxImport_Remove_Config {
    param
    (
        $Thumbprint,
        $Path
    )
    Import-DscResource -ModuleName CertificateDsc
    node localhost {
        PfxImport Integration_Test {
            Thumbprint = $Thumbprint
            Location   = 'LocalMachine'
            Store      = 'My'
            Ensure     = 'Absent'
        }
    }
}
