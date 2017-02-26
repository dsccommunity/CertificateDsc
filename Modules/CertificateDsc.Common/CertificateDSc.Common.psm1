# Import the Networking Resource Helper Module
Import-Module -Name (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) `
                               -ChildPath (Join-Path -Path 'CertificateDsc.ResourceHelper' `
                                                     -ChildPath 'CertificateDsc.ResourceHelper.psm1'))

# Import Localization Strings
$localizedData = Get-LocalizedData `
    -ResourceName 'CertificateDsc.Common' `
    -ResourcePath $PSScriptRoot

<#
    .SYNOPSIS
    Validates the existence of a file at a specific path.

    .PARAMETER Path
    The location of the file. Supports any path that Test-Path supports.

    .PARAMETER Quiet
    Returns $false if the file does not exist. By default this function throws an exception if the
    file is missing.

    .EXAMPLE
    Test-CertificatePath -Path '\\server\share\Certificates\mycert.cer'

    .EXAMPLE
    Test-CertificatePath -Path 'C:\certs\my_missing.cer' -Quiet

    .EXAMPLE
    'D:\CertRepo\a_cert.cer' | Test-CertificatePath

    .EXAMPLE
    Get-ChildItem -Path D:\CertRepo\*.cer |
        Test-CertificatePath
#>
function Test-CertificatePath
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline)]
        [String[]]
        $Path,

        [Parameter()]
        [Switch]
        $Quiet
    )

    Process
    {
        foreach ($pathNode in $Path)
        {
            if ($pathNode | Test-Path -PathType Leaf)
            {
                $true
            }
            elseif ($Quiet)
            {
                $false
            }
            else
            {
                New-InvalidArgumentError `
                    -ErrorId 'CannotFindRootedPath' `
                    -ErrorMessage ($LocalizedData.FileNotFoundError -f $pathNode)
            }
        }
    }
} # end function Test-CertificatePath

<#
    .SYNOPSIS
    Validates whether a given certificate is valid based on the hash algoritms available on the
    system.

    .PARAMETER Thumbprint
    One or more thumbprints to Test.

    .PARAMETER Quiet
    Returns $false if the thumbprint is not valid. By default this function throws an exception if
    validation fails.

    .EXAMPLE
    Test-Thumbprint fd94e3a5a7991cb6ed3cd5dd01045edf7e2284de

    .EXAMPLE
    Test-Thumbprint `
        -Thumbprint fd94e3a5a7991cb6ed3cd5dd01045edf7e2284de,0000e3a5a7991cb6ed3cd5dd01045edf7e220000 `
        -Quiet

    .EXAMPLE
    Get-ChildItem -Path Cert:\LocalMachine -Recurse |
        Where-Object -FilterScript { $_.Thumbprint } |
        Select-Object -Expression Thumbprint |
        Test-Thumbprint -Verbose
#>
function Test-Thumbprint
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Thumbprint,

        [Parameter()]
        [Switch]
        $Quiet
    )

    Begin
    {
        # Get a list of Hash Providers
        $hashProviders = [System.AppDomain]::CurrentDomain.GetAssemblies().GetTypes() |
            Where-Object -FilterScript {
                $_.BaseType.BaseType -eq [System.Security.Cryptography.HashAlgorithm] -and
                ($_.Name -cmatch 'Managed$' -or $_.Name -cmatch 'Provider$')
            }

        # Get a list of all Valid Hash types and lengths into an array
        $validHashes = @()
        foreach ($hashProvider in $hashProviders)
        {
            $bitSize = ( New-Object -TypeName $hashProvider ).HashSize
            $validHash = New-Object `
                -TypeName PSObject `
                -Property @{
                    Hash      = $hashProvider.BaseType.Name
                    BitSize   = $bitSize
                    HexLength = $bitSize / 4
                }
            $validHashes += @( $validHash )
        }
    }

    Process
    {
        foreach ($hash in $Thumbprint)
        {
            $isValid = $false

            foreach ($algorithm in $validHashes)
            {
                if ($hash -cmatch "^[a-fA-F0-9]{$($algorithm.HexLength)}$")
                {
                    Write-Verbose -Message ($LocalizedData.InvalidHashError `
                        -f $hash,$algorithm.Hash)
                    $isValid = $true
                }
            }

            if ($Quiet -or $isValid)
            {
                $isValid
            }
            else
            {
                New-InvalidArgumentError `
                    -ErrorId 'CannotFindRootedPath' `
                    -ErrorMessage ($LocalizedData.InvalidHashError -f $hash)
            }
        }
    }
} # end function Test-Thumbprint

<#
    .SYNOPSIS
    Locates one or more certificates using the passed certificate selector parameters.

    If more than one certificate is found matching the selector criteria, they will be
    returned in order of descending expiration date.

    .PARAMETER Thumbprint
    The thumbprint of the certificate to find.

    .PARAMETER FriendlyName
    The friendly name of the certificate to find.

    .PARAMETER Subject
    The subject of the certificate to find.

    .PARAMETER DNSName
    The subject alternative name of the certificate to export must contain these values.

    .PARAMETER Issuer
    The issuer of the certiicate to find.

    .PARAMETER KeyUsage
    The key usage of the certificate to find must contain these values.

    .PARAMETER EnhancedKeyUsage
    The enhanced key usage of the certificate to find must contain these values.

    .PARAMETER Store
    The Windows Certificate Store Name to search for the certificate in.
    Defaults to 'My'.

    .PARAMETER AllowExpired
    Allows expired certificates to be returned.

#>
function Find-Certificate
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param
    (
        [Parameter()]
        [String]
        $Thumbprint,

        [Parameter()]
        [String]
        $FriendlyName,

        [Parameter()]
        [String]
        $Subject,

        [Parameter()]
        [String[]]
        $DNSName,

        [Parameter()]
        [String]
        $Issuer,

        [Parameter()]
        [String[]]
        $KeyUsage,

        [Parameter()]
        [String[]]
        $EnhancedKeyUsage,

        [Parameter()]
        [String]
        $Store = 'My',

        [Parameter()]
        [Boolean]
        $AllowExpired = $false
    )

    $certPath = Join-Path -Path 'Cert:\LocalMachine' -ChildPath $Store

    if (-not (Test-Path -Path $certPath))
    {
        # The Certificte Path is not valid
        New-InvalidArgumentError `
            -ErrorId 'CannotFindCertificatePath' `
            -ErrorMessage ($LocalizedData.CertificatePathError -f $certPath)
    } # if

    # Assemble the filter to use to select the certificate
    $certFilters = @()
    if ($PSBoundParameters.ContainsKey('Thumbprint'))
    {
        $certFilters += @('($_.Thumbprint -eq $Thumbprint)')
    } # if

    if ($PSBoundParameters.ContainsKey('FriendlyName'))
    {
        $certFilters += @('($_.FriendlyName -eq $FriendlyName)')
    } # if

    if ($PSBoundParameters.ContainsKey('Subject'))
    {
        $certFilters += @('($_.Subject -eq $Subject)')
    } # if

    if ($PSBoundParameters.ContainsKey('Issuer'))
    {
        $certFilters += @('($_.Issuer -eq $Issuer)')
    } # if

    if (-not $AllowExpired)
    {
        $certFilters += @('(((Get-Date) -le $_.NotAfter) -and ((Get-Date) -ge $_.NotBefore))')
    } # if

    if ($PSBoundParameters.ContainsKey('DNSName'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject $_.DNSNameList.Unicode -DifferenceObject $DNSName | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    if ($PSBoundParameters.ContainsKey('KeyUsage'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject ($_.Extensions.KeyUsages -split ", ") -DifferenceObject $KeyUsage | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    if ($PSBoundParameters.ContainsKey('EnhancedKeyUsage'))
    {
        $certFilters += @('(@(Compare-Object -ReferenceObject ($_.EnhancedKeyUsageList.FriendlyName) -DifferenceObject $EnhancedKeyUsage | Where-Object -Property SideIndicator -eq "=>").Count -eq 0)')
    } # if

    # Join all the filters together
    $certFilterScript = '(' + ($certFilters -join ' -and ') + ')'

    Write-Verbose -Message ($LocalizedData.SearchingForCertificateUsingFilters `
        -f $store,$certFilterScript)

    $certs = Get-ChildItem -Path $certPath |
        Where-Object -FilterScript ([ScriptBlock]::Create($certFilterScript))

    # Sort the certificates
    if ($certs.count -gt 1)
    {
        $certs = $certs | Sort-Object -Descending -Property 'NotAfter'
    } # if

    return $certs
} # end function Find-Certificate

<#
    .SYNOPSIS
    Throws an InvalidArgument custom exception.

    .PARAMETER ErrorId
    The error Id of the exception.

    .PARAMETER ErrorMessage
    The error message text to set in the exception.
#>
function New-InvalidArgumentError
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorMessage
    )

    $exception = New-Object -TypeName System.ArgumentException `
        -ArgumentList $ErrorMessage
    $errorCategory = [System.Management.Automation.ErrorCategory]::InvalidArgument
    $errorRecord = New-Object -TypeName System.Management.Automation.ErrorRecord `
        -ArgumentList $exception, $ErrorId, $errorCategory, $null
    throw $errorRecord
} # end function New-InvalidArgumentError
