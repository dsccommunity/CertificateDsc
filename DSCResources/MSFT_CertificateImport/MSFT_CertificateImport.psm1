#Requires -Version 4.0

$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the Certificate Resource Common Module.
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'CertificateDsc.Common' `
            -ChildPath 'CertificateDsc.Common.psm1'))

# Import Localization Strings.
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_CertificateImport'

<#
    .SYNOPSIS
    Returns the current state of the CER Certificte file that should be imported.

    .PARAMETER Thumbprint
    The thumbprint (unique identifier) of the certificate you're importing.

    .PARAMETER Path
    The path to the CER file you want to import.
    This parameter is ignored.

    .PARAMETER Location
    The Windows Certificate Store Location to import the certificate to.

    .PARAMETER Store
    The Windows Certificate Store Name to import the certificate to.

    .PARAMETER Ensure
    Specifies whether the certificate should be present or absent.
    This parameter is ignored.

    .PARAMETER FriendlyName
    The friendly name of the certificate to set in the Windows Certificate Store.
    This parameter is ignored.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript( { $_ | Test-Thumbprint } )]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FriendlyName
    )

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($script:localizedData.GettingCertificateStatusMessage -f $Thumbprint, $Location, $Store)
        ) -join '' )

    $certificate = Get-CertificateFromCertificateStore `
        -Thumbprint $Thumbprint `
        -Location $Location `
        -Store $Store

    if ($certificate)
    {
        $Ensure = 'Present'
    }
    else
    {
        $Ensure = 'Absent'
    }

    return @{
        Thumbprint   = $Thumbprint
        Path         = $Path
        Location     = $Location
        Store        = $Store
        Ensure       = $Ensure
        FriendlyName = $certificate.FriendlyName
    }
} # end function Get-TargetResource

<#
    .SYNOPSIS
    Tests if the CER Certificate file needs to be imported or removed.

    .PARAMETER Thumbprint
    The thumbprint (unique identifier) of the certificate you're importing.

    .PARAMETER Path
    The path to the CER file you want to import.

    .PARAMETER Location
    The Windows Certificate Store Location to import the certificate to.

    .PARAMETER Store
    The Windows Certificate Store Name to import the certificate to.

    .PARAMETER Ensure
    Specifies whether the certificate should be present or absent.

    .PARAMETER FriendlyName
    The friendly name of the certificate to set in the Windows Certificate Store.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript( { $_ | Test-Thumbprint } )]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FriendlyName
    )

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($script:localizedData.TestingCertificateStatusMessage -f $Thumbprint, $Location, $Store)
        ) -join '' )

    $currentState = Get-TargetResource @PSBoundParameters

    if ($Ensure -ne $currentState.Ensure)
    {
        return $false
    }

    if ($PSBoundParameters.ContainsKey('FriendlyName') `
            -and $Ensure -eq 'Present' `
            -and $currentState.FriendlyName -ne $FriendlyName)
    {
        # The friendly name of the certificate does not match
        Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($script:localizedData.CertificateFriendlyNameMismatchMessage -f $Thumbprint, $Location, $Store, $CurrentState.FriendlyName, $FriendlyName)
        ) -join '' )

        return $false
    }

    return $true
} # end function Test-TargetResource

<#
    .SYNOPSIS
    Imports or removes the specified CER Certifiicate file.

    .PARAMETER Thumbprint
    The thumbprint (unique identifier) of the certificate you're importing.

    .PARAMETER Path
    The path to the CER file you want to import.

    .PARAMETER Location
    The Windows Certificate Store Location to import the certificate to.

    .PARAMETER Store
    The Windows Certificate Store Name to import the certificate to.

    .PARAMETER Ensure
    Specifies whether the certificate should be present or absent.

    .PARAMETER FriendlyName
    The friendly name of the certificate to set in the Windows Certificate Store.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript( { $_ | Test-Thumbprint } )]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $FriendlyName
    )

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($script:localizedData.SettingCertificateStatusMessage -f $Thumbprint, $Location, $Store)
        ) -join '' )

    if ($Ensure -ieq 'Present')
    {
        $currentState = Get-TargetResource @PSBoundParameters

        if ($currentState.Ensure -eq 'Absent')
        {
            # Import the certificate into the Store
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($script:localizedData.ImportingCertficateMessage -f $Path, $Location, $Store)
                ) -join '' )

            # Check that the certificate file exists before trying to import
            if (-not (Test-Path -Path $Path))
            {
                New-InvalidArgumentException `
                    -Message ($script:localizedData.CertificateFileNotFoundError -f $Path) `
                    -ArgumentName 'Path'
            }

            $getCertificateStorePathParameters = @{
                Location = $Location
                Store    = $Store
            }
            $certificateStore = Get-CertificateStorePath @getCertificateStorePathParameters

            $importCertificateParameters = @{
                CertStoreLocation = $certificateStore
                FilePath          = $Path
                Verbose           = $VerbosePreference
            }

            <#
                Using Import-CertificateEx instead of Import-Certificate due to the following issue:
                https://github.com/PowerShell/CertificateDsc/issues/161
            #>
            Import-CertificateEx @importCertificateParameters
        }

        if ($PSBoundParameters.ContainsKey('FriendlyName') `
                -and $currentState.FriendlyName -ne $FriendlyName)
        {
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($script:localizedData.SettingCertficateFriendlyNameMessage -f $Path, $Location, $Store, $FriendlyName)
                ) -join '' )

            $setCertificateFriendlyNameInCertificateStoreParameters = @{
                Thumbprint   = $Thumbprint
                Location     = $Location
                Store        = $Store
                FriendlyName = $FriendlyName
            }

            Set-CertificateFriendlyNameInCertificateStore @setCertificateFriendlyNameInCertificateStoreParameters
        }
    }
    else
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($script:localizedData.RemovingCertficateMessage -f $Thumbprint, $Location, $Store)
            ) -join '' )

        Remove-CertificateFromCertificateStore `
            -Thumbprint $Thumbprint `
            -Location $Location `
            -Store $Store
    }
}  # end function Test-TargetResource

Export-ModuleMember -Function *-TargetResource
