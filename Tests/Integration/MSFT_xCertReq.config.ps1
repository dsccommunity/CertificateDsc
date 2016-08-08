# This will fail if the machine does not have a CA Configured.
$CertUtilResult = & "$ENV:SystemRoot\system32\certutil.exe" @('-dump')
$CAServerFQDN = ([regex]::matches($CertUtilResult,'Server:[ \t]+`([A-Za-z0-9._-]+)''','IgnoreCase')).Groups[1].Value
$CARootName = ([regex]::matches($CertUtilResult,'Name:[ \t]+`([\sA-Za-z0-9._-]+)''','IgnoreCase')).Groups[1].Value
# If automated testing with a real CA can be performed then the credentials should be
# obtained non-interactively way - do not do this in a production environment.
$Credential = Get-Credential
$TestCertReq = [PSObject]@{
    Subject      = 'CertReq Test'
    CAServerFQDN = $CAServerFQDN
    CARootName   = $CARootName
    Credential   = $Credential
}

Configuration MSFT_xCertReq_Config {
    Import-DscResource -ModuleName xCertificate
    node localhost {
        xCertReq Integration_Test {
            Subject      = $TestCertReq.Subject
            CAServerFQDN = $TestCertReq.CAServerFQDN
            CARootName   = $TestCertReq.CARootName
            Credential   = $TestCertReq.Credential
        }
    }
}
