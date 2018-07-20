#Requires -module CertificateDsc

<#
    .DESCRIPTION
        Remove a PFX certificate from the 'My' Local Machine certificate store.
#>
Configuration Example
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName CertificateDsc

    Node localhost
    {
        PfxImport CompanyCert
        {
            Thumbprint = 'c81b94933420221a7ac004a90242d8b1d3e5070d'
            Location   = 'LocalMachine'
            Store      = 'My'
            Credential = $Credential
            Ensure     = 'Absent'
        }
    }
}
