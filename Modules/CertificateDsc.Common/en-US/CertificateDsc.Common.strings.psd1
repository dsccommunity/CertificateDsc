ConvertFrom-StringData @'
    PropertyTypeInvalidForDesiredValues = Property 'DesiredValues' must be either a [System.Collections.Hashtable], [CimInstance] or [PSBoundParametersDictionary]. The type detected was {0}.
    PropertyTypeInvalidForValuesToCheck = If 'DesiredValues' is a CimInstance, then property 'ValuesToCheck' must contain a value.
    PropertyValidationError             = Expected to find an array value for property {0} in the current values, but it was either not present or was null. This has caused the test method to return false.
    PropertiesDoesNotMatch              = Found an array for property {0} in the current values, but this array does not match the desired state. Details of the changes are below.
    PropertyThatDoesNotMatch            = {0} - {1}
    ValueOfTypeDoesNotMatch             = {0} value for property {1} does not match. Current state is '{2}' and desired state is '{3}'.
    UnableToCompareProperty             = Unable to compare property {0} as the type {1} is not handled by the Test-DscParameterState cmdlet.
    FileNotFoundError                   = File '{0}' not found.
    InvalidHashError                    = '{0}' is not a valid hash.
    CertificatePathError                = Certificate Path '{0}' is not valid.
    SearchingForCertificateUsingFilters = Looking for certificate in Store '{0}' using filter '{1}'.
    ConfigurationNamingContext          = Using the following container to look for CA candidates: 'LDAP://CN=CDP,CN=Public Key Services,CN=Services,{0}'
    DomainNotJoinedError                = The computer is not joined to a domain.
    StartLocateCAMessage                = Starting to locate CA.
    StartPingCAMessage                  = Starting to ping CA.
    NoCaFoundError                      = No Certificate Authority could be found.
    CaPingMessage                       = certutil exited with code {0} and the following output: {1}
    CaFoundMessage                      = Found certificate authority '{0}\{1}'.
    CaOnlineMessage                     = Certificate authority '{0}\{1}' is online.
    CaOfflineMessage                    = Certificate authority '{0}\{1}' is offline.
    TemplateNameResolutionError         = Failed to resolve the template name from Active Directory certificate templates '{0}'.
    TemplateNameNotFound                = No template name found in Active Directory for '{0}'.
    ActiveDirectoryTemplateSearch       = Failed to get the certificate templates from Active Directory.
    CertificateStoreNotFoundError       = Certificate Store '{0}' not found.
    RemovingCertificateFromStoreMessage = Removing certificate '{0}' from '{1}' store '{2}'.
'@
