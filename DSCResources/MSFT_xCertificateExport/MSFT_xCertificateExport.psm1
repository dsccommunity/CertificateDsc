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
    Defaults to 'My'.

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

        [System.String[]]
        $DNSName,

        [System.String]
        $Issuer,

        [System.String[]]
        $KeyUsage,

        [System.String[]]
        $EnhancedKeyUsage,

        [System.String]
        $Store = 'My',

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
        [System.Management.Automation.Credential()]
        $Password,

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
    $foundCerts = Find-Certificate @findCertificateParameters

    if ($foundCerts.Count -eq 0)
    {
        # A certificate matching the specified certificate selector parameters could not be found
        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateToExportNotFound -f $Path,$Type,$Store)
            ) -join '' )
        return $true
    }
    else
    {
        $certToExport = $foundCerts[0]
        $exportThumbprint = $certToExport.Thumbprint

        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateToExportFound -f $exportThumbprint,$Path)
            ) -join '' )

        # Export the certificate
        $exportParameters = @{
            FilePath = $Path
            Cert     = $CertToExport
            Force    = $True
        }

        if ($Type -in @('Cert','P7B','SST'))
        {
            $exportParameters += @{
                Type     = $Type
            }
            Export-Certificate @exportParameters
        }
        elseif ($Type -eq 'PFX')
        {
            $exportParameters += @{
                Password    = $Password.Password
                ChainOption = $ChainOption
            }
            if ($PSBoundParameters.ContainsKey('ProtectTo'))
            {
                $exportParameters += @{
                    ProtectTo = $ProtectTo
                }
            }
            Export-PfxCertificate @exportParameters
        }

        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateExported -f $exportThumbprint,$Path,$Type)
            ) -join '' )
    }
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
    Defaults to 'My'.

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
        $DNSName,

        [System.String[]]
        $KeyUsage,

        [System.String[]]
        $EnhancedKeyUsage,

        [System.String]
        $Store = 'My',

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
        [System.Management.Automation.Credential()]
        $Password,

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
    $foundCerts = @(Find-Certificate @findCertificateParameters)

    if ($foundCerts.Count -eq 0)
    {
        # A certificate matching the specified certificate selector parameters could not be found
        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateToExportNotFound -f $Path,$Type,$Store)
            ) -join '' )
        return $true
    }
    else
    {
        $certToExport = $foundCerts[0]
        $exportThumbprint = $certToExport.Thumbprint

        Write-Verbose -Message (
            @(
                "$($MyInvocation.MyCommand): ",
                $($LocalizedData.CertificateToExportFound -f $exportThumbprint,$Path)
            ) -join '' )

        if (Test-Path -Path $Path)
        {
            if ($MatchSource)
            {
                # The certificate has already been exported, but we need to make sure it matches
                Write-Verbose -Message (
                    @(
                        "$($MyInvocation.MyCommand): ",
                        $($LocalizedData.CertificateAlreadyExportedMatchSource -f $exportThumbprint,$Path)
                    ) -join '' )

                # Need to now compare the existing exported cert content with the found cert
                $exportedCert = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2Collection'
                if ($Type -in @('Cert','P7B','SST'))
                {
                    $exportedCert.Import($Path)
                }
                elseif ($Type -eq 'PFX')
                {
                    $exportedCert.Import($Path,$Password)
                }
                if ($exportThumbprint -notin $exportedCert.Thumbprint)
                {
                    Write-Verbose -Message (
                        @(
                            "$($MyInvocation.MyCommand): ",
                            $($LocalizedData.CertificateAlreadyExportedNotMatchSource -f $exportThumbprint,$Path)
                        ) -join '' )

                    return $false
                }
            }
            else
            {
                # This certificate is already exported and we don't want to check it is
                # the right certificate.
                Write-Verbose -Message (
                    @(
                        "$($MyInvocation.MyCommand): ",
                        $($LocalizedData.CertificateAlreadyExported -f $exportThumbprint,$Path)
                    ) -join '' )

            }
            return $true
        }
        else
        {
            # The found certificate has not been exported yet
            Write-Verbose -Message (
                @(
                    "$($MyInvocation.MyCommand): ",
                    $($LocalizedData.CertificateNotExported -f $exportThumbprint,$Path)
                ) -join '' )

            return $false
        }
    }
}  # end function Test-TargetResource

Export-ModuleMember -Function *-TargetResource
