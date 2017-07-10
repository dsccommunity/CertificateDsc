Configuration MSFT_xWaitForCertificateServices_Config {
    Import-DscResource -ModuleName xCertificate

    node localhost {
        xWaitForCertificateServices Integration_Test {
            CAServerFQDN        = $Node.CAServerFQDN
            CARootName          = $Node.CARootName
            RetryIntervalSeconds    = $Node.RetryIntervalSeconds
            RetryCount          = $Node.RetryCount
        }
    }
}
