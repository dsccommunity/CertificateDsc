ConvertFrom-StringData @'
    GettingCertificateExportMessage          = Getting certificate export status to '{0}'.
    SettingCertificateExportMessage          = Setting certificate export status to '{0}'.
    TestingCertificateExportMessage          = Testing certificate export status to '{0}'.
    CertificateToExportNotFound              = Could not find certificate to Export to '{0}' as '{1}' in LocalMachine '{2}' store.
    CertificateToExportFound                 = Certificate to export with thumbprint '{0}' found to export to '{1}'.
    CertificateAlreadyExported               = Certificate to export with thumbprint '{0}' has already been exported to '{1}'. MatchSource set to false so not checking content match. Will not export.
    CertificateAlreadyExportedMatchSource    = Certificate to Export with thumbprint '{0}' has already been exported to '{1}'. MatchSource set to true so checking content match.
    CertificateAlreadyExportedNotMatchSource = Certificate to Export with thumbprint '{0}' has already been exported to '{1}'. but exported certificate does not contain expected thumbprint. Will export.
    CertificateNotExported                   = Certificate to export with thumbprint '{0}' has not yet been exported to '{1}'. Will export.
    CertificateExported                      = Certificate to export as '{2}' with thumbprint '{0}' was exported to '{1}'.
'@
