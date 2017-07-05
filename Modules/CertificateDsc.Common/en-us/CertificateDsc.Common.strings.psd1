ConvertFrom-StringData @'
    FileNotFoundError                   = File '{0}' not found.
    InvalidHashError                    = '{0}' is not a valid hash.
    CertificatePathError                = Certificate Path '{0}' is not valid.
    SearchingForCertificateUsingFilters = Looking for certificate in Store '{0}' using filter '{1}'.
    ConfigurationNamingContext          = Using the following container to look for CA candidates: 'LDAP://CN=CDP,CN=Public Key Services,CN=Services,{0}'
    ValidHashMessage                    = '{0}' is a valid {1} hash.
    DomainContactError                  = The domain '{0}' could not be contacted. The following error was received: '{1}'
    StartLocateCAMessage                = Starting to locate CA
    NoCaFoundError                      = No Certificate Authority could be found in Configuration Naming Context '{0}'
    CaPingMessage                       = certutil exited with code {0} and the following output:`r`n{1}
    CaFoundMessage                      = Found certificate authority {0}\{1}
'@
