ConvertFrom-StringData @'
    GettingCertReqStatusMessage = Getting Certificate with Subject '{0}' Issuer '{1}', FriendlyName '{2}' and CertificateTemplate '{3}'.
    CertificateExistsMessage = Certificate with Subject '{0}' Issuer {1}, FriendlyName '{2}' and CertificateTemplate '{3}' found with Thumbprint '{4}'.
    StartingCertReqMessage = Starting Certificate request with Subject '{0}', Issuer '{1}', FriendlyName '{2}' and CertificateTemplate '{3}'.
    CreateRequestCertificateMessage = Creating certificate request '{1}' from '{0}'.
    CreateRequestResultCertificateMessage = Create certificate request result: {0}
    SubmittingRequestCertificateMessage = Submitting certificate request '{0}' returning '{1}' issued by {2}.
    SubmittingRequestProcessCertificateMessage = Submitting certificate request using separate process.
    SubmittingRequestResultCertificateMessage = Submitting certificate request result: {0}
    AcceptingRequestCertificateMessage = Accepting certificate '{1}' issued by {0}.
    AcceptingRequestResultCertificateMessage = Accepting certificate result: {0}
    CleaningUpRequestFilesMessage = Cleaning up certificate request files '{0}'.
    TestingCertReqStatusMessage = Testing Certificate with Subject '{0}' Issuer '{1}', FriendlyName '{2}' and CertificateTemplate '{3}'.
    ExpiringCertificateMessage = The certificate found with Subject '{0}' Issuer '{1}', FriendlyName '{2}' and CertificateTemplate '{3}' is about to expire.
    NoValidCertificateMessage = No valid certificate found with Subject '{0}' Issuer '{1}', FriendlyName '{2}' and CertificateTemplate '{3}'.
    ExpiredCertificateMessage = The certificate found with Subject '{0}' Issuer '{1}', FriendlyName '{2}' and CertificateTemplate '{3}' has expired: {4}.
    ValidCertificateExistsMessage = Valid certificate found with Subject '{0}' Issuer '{1}', FriendlyName '{2}' and CertificateTemplate '{3}': {4}
    CertificateReqNotFoundError = Certificate Request file '{0}' not found.
    CertificateCerNotFoundError = Certificate file '{0}' not found.
    CertReqOutNotFoundError = CertReq.exe output file '{0}' not found.
    CertTemplateMismatch = The certificate with Subject '{0}' Issuer '{1}', FriendlyName '{2}' with Thumbprint '{3}' has the wrong template: {4}.
    CertFriendlyNameMismatch = The certificate with Subject '{0}', Issuer '{1}', CertificateTemplate '{2}' and Thumbprint '{3}' has the wrong friendly name: {4}.
    InvalidKeySize = The key length '{0}' specified is invalid for '{1}' key types.
    GenericErrorThrown = A Generic Error was thrown when accepting a Certificate. It threw the following Error message: {0}
'@
