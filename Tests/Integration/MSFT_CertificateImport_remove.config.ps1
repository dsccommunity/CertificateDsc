Configuration MSFT_CertificateImport_Remove_Config {
    param
    (
        $Thumbprint,
        $Path
    )
    Import-DscResource -ModuleName CertificateDsc
    node localhost {
        CertificateImport Integration_Test {
            Thumbprint = $Thumbprint
            Path       = $Path
            Location   = 'LocalMachine'
            Store      = 'My'
            Ensure     = 'Absent'
        }
    }
}
