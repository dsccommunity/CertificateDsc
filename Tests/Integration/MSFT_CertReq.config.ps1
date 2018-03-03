Configuration MSFT_xCertReq_Config {
    Import-DscResource -ModuleName xCertificate

    node localhost {
        xCertReq Integration_Test {
            Subject             = $Node.Subject
            CAServerFQDN        = $Node.CAServerFQDN
            CARootName          = $Node.CARootName
            Credential          = $Node.Credential
            KeyLength           = $Node.KeyLength
            Exportable          = $Node.Exportable
            ProviderName        = $Node.ProviderName
            OID                 = $Node.OID
            KeyUsage            = $Node.KeyUsage
            CertificateTemplate = $Node.CertificateTemplate
            SubjectAltName      = $Node.SubjectAltName
            FriendlyName        = $Node.FriendlyName
        }
    }
}
