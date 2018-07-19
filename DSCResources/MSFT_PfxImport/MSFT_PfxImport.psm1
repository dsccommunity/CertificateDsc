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
    -ResourceName 'MSFT_PfxImport' `
    -ResourcePath (Split-Path -Parent $Script:MyInvocation.MyCommand.Path)

<#
    .SYNOPSIS
    Returns the current state of the PFX Certificte file that should be imported.

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
    This parameter is ignored.

    .PARAMETER Credential
    A `PSCredential` object that is used to decrypt the PFX file. Only the
    password is used, so any user name is valid.
    This parameter is ignored.

    .PARAMETER Ensure
    Specifies whether the PFX file should be present or absent.
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
        $Ensure = 'Present'
    )

    $certificateStore = Get-CertificateStorePath -Location $Location -Store $Store

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.GettingPfxStatusMessage -f $Thumbprint, $certificateStore)
        ) -join '' )

    if ((Test-Path -Path $certificateStore) -eq $false)
    {
        New-InvalidArgumentException `
            -Message ($LocalizedData.CertificateStoreNotFoundError -f $certificateStore) `
            -ArgumentName 'Store'
    }

    # Check that the certificate PFX file exists
    if ($Ensure -eq 'Present' -and `
        (-not (Test-CertificatePath -Path $Path)))
    {
        New-InvalidArgumentException `
            -Message ($LocalizedData.CertificatePfxFileNotFoundError -f $Path) `
            -ArgumentName 'Path'
    }

    # Look up the certificate
    $certificatePath = Join-Path -Path $certificateStore -ChildPath $Thumbprint
    $certificate = Get-ChildItem -Path $certificatePath -ErrorAction SilentlyContinue

    if ($certificate)
    {
        if ($certificate.HasPrivateKey)
        {
            # If the certificate is found and has a private key then consider it Present
            Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.CertificateInstalledMessage -f $Thumbprint, $certificateStore)
            ) -join '' )

            $Ensure = 'Present'
        }
        else
        {
            # The certificate is found but the private key is missing so it is Absent
            Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.CertificateInstalledNoPrivateKeyMessage -f $Thumbprint, $certificateStore)
            ) -join '' )

            $Ensure = 'Absent'
        }
    }
    else
    {
        # The certificate is not found
        Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.CertificateNotInstalledMessage -f $Thumbprint, $certificateStore)
        ) -join '' )

        $Ensure = 'Absent'
    }

    return @{
        Thumbprint = $Thumbprint
        Path       = $Path
        Location   = $Location
        Store      = $Store
        Exportable = $Exportable
        Credential = $Credential
        Ensure     = $Ensure
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
        $Ensure = 'Present'
    )

    $result = Get-TargetResource @PSBoundParameters

    $certificateStore = Get-CertificateStorePath -Location $Location -Store $Store

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.TestingPfxStatusMessage -f $Thumbprint, $certificateStore)
        ) -join '' )

    if ($Ensure -ne $result.Ensure)
    {
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
        $Ensure = 'Present'
    )

    $certificateStore = Get-CertificateStorePath -Location $Location -Store $Store

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.SettingPfxStatusMessage -f $Thumbprint, $certificateStore)
        ) -join '' )

    if ($Ensure -ieq 'Present')
    {
        # Import the certificate into the Store
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.ImportingPfxMessage -f $Path, $certificateStore)
            ) -join '' )

        $importPfxCertificateParameters = @{
            Exportable        = $Exportable
            CertStoreLocation = $certificateStore
            FilePath          = $Path
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
    elseif ($Ensure -ieq 'Absent')
    {
        # Remove the certificate from the Store
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.RemovingPfxMessage -f $Thumbprint, $certificateStore)
            ) -join '' )

        $null = Get-ChildItem -Path $certificateStore |
            Where-Object -FilterScript {
                $_.Thumbprint -ieq $thumbprint
            } |
            Remove-Item -Force
    }
} # end function Set-TargetResource

Export-ModuleMember -Function *-TargetResource
