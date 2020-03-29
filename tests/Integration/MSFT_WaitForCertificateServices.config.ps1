Configuration MSFT_WaitForCertificateServices_Config {
    Import-DscResource -ModuleName CertificateDsc

    node localhost {
        WaitForCertificateServices Integration_Test {
            CAServerFQDN         = $Node.CAServerFQDN
            CARootName           = $Node.CARootName
            RetryIntervalSeconds = $Node.RetryIntervalSeconds
            RetryCount           = $Node.RetryCount
        }
    }
}
