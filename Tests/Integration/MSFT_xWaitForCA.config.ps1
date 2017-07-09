Configuration MSFT_xWaitForCA_Config {
    Import-DscResource -ModuleName xCertificate

    node localhost {
        xWaitForCA Integration_Test {
            CAServerFQDN        = $Node.CAServerFQDN
            CARootName          = $Node.CARootName
            RetryIntervalSec    = $Node.RetryIntervalSec
            RetryCount          = $Node.RetryCount
        }
    }
}
