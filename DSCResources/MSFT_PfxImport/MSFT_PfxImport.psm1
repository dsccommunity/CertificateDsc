#Requires -Version 4.0

$modulePath = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'Modules'

# Import the Certificate Resource Common Module.
Import-Module -Name (Join-Path -Path $modulePath `
        -ChildPath (Join-Path -Path 'CertificateDsc.Common' `
            -ChildPath 'CertificateDsc.Common.psm1'))

# Import Localization Strings.
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_PfxImport'

<#
    .SYNOPSIS
    Returns the current state of the PFX Certificte file that should be imported.

    .PARAMETER Thumbprint
    The thumbprint (unique identifier) of the PFX file you're importing.

    .PARAMETER Path
    The path to the PFX file you want to import.
    This parameter is ignored.

    .PARAMETER Location
    The Windows Certificate Store Location to import the PFX file to.

    .PARAMETER Store
    The Windows Certificate Store Name to import the PFX file to.

    .PARAMETER Exportable
    Determines whether the private key is exportable from the machine after
    it has been imported.
    This parameter is ignored.

    .PARAMETER Credential
    A `PSCredential` object that is used to decrypt the PFX file. Only the
    password is used, so any user name is valid.
    This parameter is ignored.

    .PARAMETER Ensure
    Specifies whether the PFX file should be present or absent.
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

        [Parameter()]
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
        [System.Boolean]
        $Exportable = $false,

        [Parameter()]
        [PSCredential]
        $Credential,

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
            $($script:localizedData.GettingPfxStatusMessage -f $Thumbprint, $Location, $Store)
        ) -join '' )

    $certificate = Get-CertificateFromCertificateStore `
        -Thumbprint $Thumbprint `
        -Location $Location `
        -Store $Store

    if ($certificate)
    {
        if ($certificate.HasPrivateKey)
        {
            # If the certificate is found and has a private key then consider it Present
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($script:localizedData.CertificateInstalledMessage -f $Thumbprint, $Location, $Store)
                ) -join '' )

            $Ensure = 'Present'
        }
        else
        {
            # The certificate is found but the private key is missing so it is Absent
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($script:localizedData.CertificateInstalledNoPrivateKeyMessage -f $Thumbprint, $Location, $Store)
                ) -join '' )

            $Ensure = 'Absent'
        }
    }
    else
    {
        # The certificate is not found
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($script:localizedData.CertificateNotInstalledMessage -f $Thumbprint, $Location, $Store)
            ) -join '' )

        $Ensure = 'Absent'
    }

    return @{
        Thumbprint   = $Thumbprint
        Path         = $Path
        Location     = $Location
        Store        = $Store
        Exportable   = $Exportable
        Credential   = $Credential
        Ensure       = $Ensure
        FriendlyName = $certificate.FriendlyName
    }
} # end function Get-TargetResource

<#
    .SYNOPSIS
    Tests if the PFX Certificate file needs to be imported or removed.

    .PARAMETER Thumbprint
    The thumbprint (unique identifier) of the PFX file you're importing.

    .PARAMETER Path
    The path to the PFX file you want to import.

    .PARAMETER Location
    The Windows Certificate Store Location to import the PFX file to.

    .PARAMETER Store
    The Windows Certificate Store Name to import the PFX file to.

    .PARAMETER Exportable
    Determines whether the private key is exportable from the machine after
    it has been imported.

    .PARAMETER Credential
    A `PSCredential` object that is used to decrypt the PFX file. Only the
    password is used, so any user name is valid.

    .PARAMETER Ensure
    Specifies whether the PFX file should be present or absent.

    .PARAMETER FriendlyName
    The friendly name of the certificate to set in the Windows Certificate Store.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript( { $_ | Test-Thumbprint } )]
        [System.String]
        $Thumbprint,

        [Parameter()]
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
        [System.Boolean]
        $Exportable = $false,

        [Parameter()]
        [PSCredential]
        $Credential,

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
            $($script:localizedData.TestingPfxStatusMessage -f $Thumbprint, $Location, $Store)
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
    Imports or removes the specified PFX Certifiicate file.

    .PARAMETER Thumbprint
    The thumbprint (unique identifier) of the PFX file you're importing.

    .PARAMETER Path
    The path to the PFX file you want to import.

    .PARAMETER Location
    The Windows Certificate Store Location to import the PFX file to.

    .PARAMETER Store
    The Windows Certificate Store Name to import the PFX file to.

    .PARAMETER Exportable
    Determines whether the private key is exportable from the machine after
    it has been imported.

    .PARAMETER Credential
    A `PSCredential` object that is used to decrypt the PFX file. Only the
    password is used, so any user name is valid.

    .PARAMETER Ensure
    Specifies whether the PFX file should be present or absent.

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

        [Parameter()]
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
        [System.Boolean]
        $Exportable = $false,

        [Parameter()]
        [PSCredential]
        $Credential,

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
            $($script:localizedData.SettingPfxStatusMessage -f $Thumbprint, $Location, $Store)
        ) -join '' )

    if ($Ensure -ieq 'Present')
    {
        $currentState = Get-TargetResource @PSBoundParameters

        if ($currentState.Ensure -eq 'Absent')
        {
            # Import the certificate into the Store
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($script:localizedData.ImportingPfxMessage -f $Path, $Location, $Store)
                ) -join '' )

            # Check that the certificate PFX file exists before trying to import
            if (-not (Test-Path -Path $Path))
            {
                New-InvalidArgumentException `
                    -Message ($script:localizedData.CertificatePfxFileNotFoundError -f $Path) `
                    -ArgumentName 'Path'
            }

            $getCertificateStorePathParameters = @{
                Location = $Location
                Store    = $Store
            }
            $certificateStore = Get-CertificateStorePath @getCertificateStorePathParameters

            $importPfxCertificateParameters = @{
                Exportable        = $Exportable
                CertStoreLocation = $certificateStore
                FilePath          = $Path
                Verbose           = $VerbosePreference
            }

            if ($Credential)
            {
                $importPfxCertificateParameters['Password'] = $Credential.Password
            }

            # If the built in PKI cmdlet exists then use that, otherwise command in Common module.
            if (Test-CommandExists -Name 'Import-PfxCertificate')
            {
                Import-PfxCertificate @importPfxCertificateParameters
            }
            else
            {
                Import-PfxCertificateEx @importPfxCertificateParameters
            }
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
} # end function Set-TargetResource

Export-ModuleMember -Function *-TargetResource
