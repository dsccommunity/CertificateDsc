Configuration MSFT_xWaitForCertificateServices_Config {
    Import-DscResource -ModuleName xCertificate

    node localhost {
        xWaitForCertificateServices Integration_Test {
            CAServerFQDN        = $Node.CAServerFQDN
            CARootName          = $Node.CARootName
            RetryIntervalSec    = $Node.RetryIntervalSec
            RetryCount          = $Node.RetryCount
        }
    }
}
