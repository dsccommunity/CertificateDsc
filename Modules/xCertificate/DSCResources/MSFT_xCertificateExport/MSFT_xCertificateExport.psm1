#Requires -Version 4.0

$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the Certificate Common Modules
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'CertificateDsc.Common' `
            -ChildPath 'CertificateDsc.Common.psm1'))

# Import the Certificate Resource Helper Module
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'CertificateDsc.ResourceHelper' `
            -ChildPath 'CertificateDsc.ResourceHelper.psm1'))

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

    Write-Verbose -Message (
        @(
            "$($MyInvocation.MyCommand): ",
            $($LocalizedData.GettingCertificateExportMessage -f $Path)
        ) -join '' )

    $result = @{
        Path       = $Path
        IsExported = (Test-Path -Path $Path)
    }

    return $result
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

    .PARAMETER DNSName
    The subject alternative name of the certificate to export must contain these values.
    Certificate selector parameter.

    .PARAMETER Issuer
    The issuer of the certificate to export.
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
    Defaults to 'My'.

    .PARAMETER AllowExpired
    Allow an expired certificate to be exported.
    Certificate selector parameter.

    .PARAMETER MatchSource
    Causes an existing exported certificate to be compared with the certificate identified for
    export and re-exported if it does not match.

    .PARAMETER Type
    Specifies the type of certificate to export.
    Defaults to 'Cert'.

    .PARAMETER ChainOption
    Specifies the options for building a chain when exporting a PFX certificate.
    Defaults to 'BuildChain'.

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

        [Parameter()]
        [System.String]
        $Thumbprint,

        [Parameter()]
        [System.String]
        $FriendlyName,

        [Parameter()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String[]]
        $DNSName,

        [Parameter()]
        [System.String]
        $Issuer,

        [Parameter()]
        [System.String[]]
        $KeyUsage,

        [Parameter()]
        [System.String[]]
        $EnhancedKeyUsage,

        [Parameter()]
        [System.String]
        $Store = 'My',

        [Parameter()]
        [System.Boolean]
        $AllowExpired,

        [Parameter()]
        [System.Boolean]
        $MatchSource,

        [Parameter()]
        [ValidateSet("Cert", "P7B", "SST", "PFX")]
        [System.String]
        $Type = 'Cert',

        [Parameter()]
        [ValidateSet("BuildChain", "EndEntityCertOnly")]
        [System.String]
        $ChainOption = 'BuildChain',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Password,

        [Parameter()]
        [System.String[]]
        $ProtectTo
    )

    Write-Verbose -Message (
        @(
            "$($MyInvocation.MyCommand): ",
            $($LocalizedData.SettingCertificateExportMessage -f $Path)
        ) -join '' )

    $findCertificateParameters = @{} + $PSBoundParameters
    $null = $findCertificateParameters.Remove('Path')
    $null = $findCertificateParameters.Remove('MatchSource')
    $null = $findCertificateParameters.Remove('Type')
    $null = $findCertificateParameters.Remove('ChainOption')
    $null = $findCertificateParameters.Remove('Password')
    $null = $findCertificateParameters.Remove('ProtectTo')
    $foundCertificates = @(Find-Certificate @findCertificateParameters)

    if ($foundCertificates.Count -eq 0)
    {
        # A certificate matching the specified certificate selector parameters could not be found
        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateToExportNotFound -f $Path, $Type, $Store)
            ) -join '' )
    }
    else
    {
        $certificateToExport = $foundCertificates[0]
        $certificateThumbprintToExport = $certificateToExport.Thumbprint

        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateToExportFound -f $certificateThumbprintToExport, $Path)
            ) -join '' )

        # Export the certificate
        $exportCertificateParameters = @{
            FilePath = $Path
            Cert     = $certificateToExport
            Force    = $true
        }

        if ($Type -in @('Cert', 'P7B', 'SST'))
        {
            $exportCertificateParameters += @{
                Type = $Type
            }
            Export-Certificate @exportCertificateParameters
        }
        elseif ($Type -eq 'PFX')
        {
            $exportCertificateParameters += @{
                Password    = $Password.Password
                ChainOption = $ChainOption
            }

            if ($PSBoundParameters.ContainsKey('ProtectTo'))
            {
                $exportCertificateParameters += @{
                    ProtectTo = $ProtectTo
                }
            } # if
            Export-PfxCertificate @exportCertificateParameters
        } # if

        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateExported -f $certificateThumbprintToExport, $Path, $Type)
            ) -join '' )
    } # if
} # end function Set-TargetResource

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

    .PARAMETER DNSName
    The subject alternative name of the certificate to export must contain these values.
    Certificate selector parameter.

    .PARAMETER Issuer
    The issuer of the certificate to export.
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
    Defaults to 'My'.

    .PARAMETER AllowExpired
    Allow an expired certificate to be exported.
    Certificate selector parameter.

    .PARAMETER MatchSource
    Causes an existing exported certificate to be compared with the certificate identified for
    export and re-exported if it does not match.

    .PARAMETER Type
    Specifies the type of certificate to export.
    Defaults to 'Cert'.

    .PARAMETER ChainOption
    Specifies the options for building a chain when exporting a PFX certificate.
    Defaults to 'BuildChain'.

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

        [Parameter()]
        [System.String]
        $Thumbprint,

        [Parameter()]
        [System.String]
        $FriendlyName,

        [Parameter()]
        [System.String]
        $Subject,

        [Parameter()]
        [System.String]
        $Issuer,

        [Parameter()]
        [System.String[]]
        $DNSName,

        [Parameter()]
        [System.String[]]
        $KeyUsage,

        [Parameter()]
        [System.String[]]
        $EnhancedKeyUsage,

        [Parameter()]
        [System.String]
        $Store = 'My',

        [Parameter()]
        [System.Boolean]
        $AllowExpired,

        [Parameter()]
        [System.Boolean]
        $MatchSource,

        [Parameter()]
        [ValidateSet("Cert", "P7B", "SST", "PFX")]
        [System.String]
        $Type = 'Cert',

        [Parameter()]
        [ValidateSet("BuildChain", "EndEntityCertOnly")]
        [System.String]
        $ChainOption = 'BuildChain',

        [Parameter()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Password,

        [Parameter()]
        [System.String[]]
        $ProtectTo
    )

    Write-Verbose -Message (
        @(
            "$($MyInvocation.MyCommand): ",
            $($LocalizedData.TestingCertificateExportMessage -f $Path)
        ) -join '' )

    $findCertificateParameters = @{} + $PSBoundParameters
    $null = $findCertificateParameters.Remove('Path')
    $null = $findCertificateParameters.Remove('MatchSource')
    $null = $findCertificateParameters.Remove('Type')
    $null = $findCertificateParameters.Remove('ChainOption')
    $null = $findCertificateParameters.Remove('Password')
    $null = $findCertificateParameters.Remove('ProtectTo')
    $foundCertificates = @(Find-Certificate @findCertificateParameters)

    if ($foundCertificates.Count -eq 0)
    {
        # A certificate matching the specified certificate selector parameters could not be found
        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateToExportNotFound -f $Path, $Type, $Store)
            ) -join '' )

        return $true
    }
    else
    {
        $certificateToExport = $foundCertificates[0]
        $certificateThumbprintToExport = $certificateToExport.Thumbprint

        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateToExportFound -f $certificateThumbprintToExport, $Path)
            ) -join '' )

        if (Test-Path -Path $Path)
        {
            if ($MatchSource)
            {
                # The certificate has already been exported, but we need to make sure it matches
                Write-Verbose -Message (
                    @(
                        "$($MyInvocation.MyCommand): ",
                        $($LocalizedData.CertificateAlreadyExportedMatchSource -f $certificateThumbprintToExport, $Path)
                    ) -join '' )

                # Need to now compare the existing exported cert content with the found cert
                $exportedCertificate = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2Collection'
                if ($Type -in @('Cert', 'P7B', 'SST'))
                {
                    $exportedCertificate.Import($Path)
                }
                elseif ($Type -eq 'PFX')
                {
                    $exportedCertificate.Import($Path, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                } # if

                if ($certificateThumbprintToExport -notin $exportedCertificate.Thumbprint)
                {
                    Write-Verbose -Message (
                        @(
                            "$($MyInvocation.MyCommand): ",
                            $($LocalizedData.CertificateAlreadyExportedNotMatchSource -f $certificateThumbprintToExport, $Path)
                        ) -join '' )

                    return $false
                } # if
            }
            else
            {
                # This certificate is already exported and we don't want to check it is
                # the right certificate.
                Write-Verbose -Message (
                    @(
                        "$($MyInvocation.MyCommand): ",
                        $($LocalizedData.CertificateAlreadyExported -f $certificateThumbprintToExport, $Path)
                    ) -join '' )
            } # if

            return $true
        }
        else
        {
            # The found certificate has not been exported yet
            Write-Verbose -Message (
                @(
                    "$($MyInvocation.MyCommand): ",
                    $($LocalizedData.CertificateNotExported -f $certificateThumbprintToExport, $Path)
                ) -join '' )

            return $false
        } # if
    } # if
}  # end function Test-TargetResource

Export-ModuleMember -Function *-TargetResource
