#Requires -Version 4.0

$script:ResourceRootPath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent)

# Import the xNetworking Resource Module (to import the common modules)
Import-Module -Name (Join-Path -Path $script:ResourceRootPath -ChildPath 'xCertificate.psd1')

# Import Localization Strings
$localizedData = Get-LocalizedData `
    -ResourceName 'MSFT_xCertificateExport' `
    -ResourcePath (Split-Path -Parent $Script:MyInvocation.MyCommand.Path)

<#
    .SYNOPSIS
    Returns the current state of the exported certificate.

    .PARAMETER Path
    The path to the file you that will contain the exported certificate.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )
} # end function Get-TargetResource

<#
    .SYNOPSIS
    Exports the certificate.

    .PARAMETER Path
    The path to the file you that will contain the exported certificate.

    .PARAMETER Thumbprint
    The thumbprint of the certificate to export.
    Certificate selector parameter.

    .PARAMETER FriendlyName
    The friendly name of the certificate to export.
    Certificate selector parameter.

    .PARAMETER Subject
    The subject of the certificate to export.
    Certificate selector parameter.

    .PARAMETER Issuer
    The issuer of the certiicate to export.
    Certificate selector parameter.

    .PARAMETER KeyUsage
    The key usage of the certificate to export must contain these values.
    Certificate selector parameter.

    .PARAMETER EnhancedKeyUsage
    The enhanced key usage of the certificate to export must contain these values.
    Certificate selector parameter.

    .PARAMETER Store
    The Windows Certificate Store Name to search for the certificate to export from.
    Certificate selector parameter.

    .PARAMETER AllowExpired
    Allow an expired certificate to be exported.
    Certificate selector parameter.

    .PARAMETER MatchSource
    Causes an existing exported certificate to be compared with the certificate identified for
    export and re-exported if it does not match.

    .PARAMETER Type
    Specifies the type of certificate to export.

    .PARAMETER ChainOption
    Specifies the options for building a chain when exporting a PFX certificate.

    .PARAMETER Password
    Specifies the password used to protect an exported PFX file.

    .PARAMETER ProtectTo
    Specifies an array of strings for the username or group name that can access the private
    key of an exported PFX file without any password.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [System.String]
        $Thumbprint,

        [System.String]
        $FriendlyName,

        [System.String]
        $Subject,

        [System.String]
        $Issuer,

        [System.String[]]
        $KeyUsage,

        [System.String[]]
        $EnhancedKeyUsage,

        [System.String]
        $Store,

        [System.Boolean]
        $AllowExpired,

        [System.Boolean]
        $MatchSource,

        [ValidateSet("Cert","P7B","SST","PFX")]
        [System.String]
        $Type = 'Cert',

        [ValidateSet("BuildChain","EndEntityCertOnly")]
        [System.String]
        $ChainOption = 'BuildChain',

        [System.Management.Automation.PSCredential]
        $Password,

        [System.String[]]
        $ProtectTo
    )

} # end function Test-TargetResource

<#
    .SYNOPSIS
    Tests the state of the currently exported certificate.

    .PARAMETER Path
    The path to the file you that will contain the exported certificate.

    .PARAMETER Thumbprint
    The thumbprint of the certificate to export.
    Certificate selector parameter.

    .PARAMETER FriendlyName
    The friendly name of the certificate to export.
    Certificate selector parameter.

    .PARAMETER Subject
    The subject of the certificate to export.
    Certificate selector parameter.

    .PARAMETER Issuer
    The issuer of the certiicate to export.
    Certificate selector parameter.

    .PARAMETER KeyUsage
    The key usage of the certificate to export must contain these values.
    Certificate selector parameter.

    .PARAMETER EnhancedKeyUsage
    The enhanced key usage of the certificate to export must contain these values.
    Certificate selector parameter.

    .PARAMETER Store
    The Windows Certificate Store Name to search for the certificate to export from.
    Certificate selector parameter.

    .PARAMETER AllowExpired
    Allow an expired certificate to be exported.
    Certificate selector parameter.

    .PARAMETER MatchSource
    Causes an existing exported certificate to be compared with the certificate identified for
    export and re-exported if it does not match.

    .PARAMETER Type
    Specifies the type of certificate to export.

    .PARAMETER ChainOption
    Specifies the options for building a chain when exporting a PFX certificate.

    .PARAMETER Password
    Specifies the password used to protect an exported PFX file.

    .PARAMETER ProtectTo
    Specifies an array of strings for the username or group name that can access the private
    key of an exported PFX file without any password.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [System.String]
        $Thumbprint,

        [System.String]
        $FriendlyName,

        [System.String]
        $Subject,

        [System.String]
        $Issuer,

        [System.String[]]
        $KeyUsage,

        [System.String[]]
        $EnhancedKeyUsage,

        [System.String]
        $Store,

        [System.Boolean]
        $AllowExpired,

        [System.Boolean]
        $MatchSource,

        [ValidateSet("Cert","P7B","SST","PFX")]
        [System.String]
        $Type = 'Cert',

        [ValidateSet("BuildChain","EndEntityCertOnly")]
        [System.String]
        $ChainOption = 'BuildChain',

        [System.Management.Automation.PSCredential]
        $Password,

        [System.String[]]
        $ProtectTo
    )

}  # end function Test-TargetResource

Export-ModuleMember -Function *-TargetResource
