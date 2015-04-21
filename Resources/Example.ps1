configuration SSL
{
    param (
        [Parameter(Mandatory=$true)] 
        [ValidateNotNullorEmpty()] 
        [PsCredential] $Credential 
        )
    Import-DscResource -ModuleName xCertificate
    Node 'localhost'
    {
	    xCertReq SSLCert
	    {
		    CARootName                = 'test-dc01-ca'
		    CAServerFQDN              = 'dc01.test.pha'
		    Subject                   = 'foodomain.test.net'
		    AutoRenew                 = $true
		    Credential                = $Credential
	    }
    }
}
$configData = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost';
            PSDscAllowPlainTextPassword = $true
            }
        )
    }
SSL -ConfigurationData $configData -Credential (get-credential) -OutputPath 'c:\SSLConfig'
Start-DscConfiguration -Wait -Force -Verbose -Path 'c:\SSLConfig'

# Validate results
Get-ChildItem Cert:\LocalMachine\My