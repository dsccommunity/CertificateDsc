# Suppressed as per PSSA Rule Severity guidelines for unit/integration tests:
# https://github.com/PowerShell/DscResources/blob/master/PSSARuleSeverities.md
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

# Import the Certificate PDT Helper Module
Import-Module -Name (Join-Path -Path $modulePath `
                               -ChildPath (Join-Path -Path 'CertificateDsc.PDT' `
                                                     -ChildPath 'CertificateDsc.PDT.psm1'))

# Import Localization Strings
$localizedData = Get-LocalizedData `
    -ResourceName 'MSFT_xWaitForCertificateServices' `
    -ResourcePath (Split-Path -Parent $Script:MyInvocation.MyCommand.Path)

<#
    .SYNOPSIS
    Returns the current state of the wait for Active Directory Certificate
    Service Certificate Authority resource.

    .PARAMETER CAServerFQDN
    The FQDN of the Active Directory Certificate Service Certificate Authority to wait
    for. Leave empty to automatically detect.

    .PARAMETER CARootName
    The name of the Active Directory Certificate Service Certificate Authority to wait
    for. Leave empty to automatically detect.

    .PARAMETER RetryIntervalSec
    Specifies the number of seconds to wait for the Active Directory Certificate
    Service Certificate Authority to become available.

    .PARAMETER RetryCount
    The number of times to loop the retry interval while waiting for the Active
    Directory Certificate Service Certificate Authority.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $CAServerFQDN,

        [parameter(Mandatory = $true)]
        [System.String]
        $CARootName,

        [Parameter()]
        [System.UInt32]
        $RetryIntervalSec = 10,

        [Parameter()]
        [System.UInt32]
        $RetryCount = 60
    )

    $ca = "$CAServerFQDN\$CARootName"

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($localizedData.GettingWaitForCAStatusMessage -f $ca)
        ) -join '' )

    $returnValue = @{
        CAServerFQDN     = $CAServerFQDN
        CARootName       = $CARootName
        RetryIntervalSec = $RetryIntervalSec
        RetryCount       = $RetryCount
    }
    return $returnValue
} # function Get-TargetResource

<#
    .SYNOPSIS
    Waits for the Active Directory Certificate Service Certificate Authority to become
    available or times out.

    .PARAMETER CAServerFQDN
    The FQDN of the Active Directory Certificate Service Certificate Authority to wait
    for. Leave empty to automatically detect.

    .PARAMETER CARootName
    The name of the Active Directory Certificate Service Certificate Authority to wait
    for. Leave empty to automatically detect.

    .PARAMETER RetryIntervalSec
    Specifies the number of seconds to wait for the Active Directory Certificate
    Service Certificate Authority to become available.

    .PARAMETER RetryCount
    The number of times to loop the retry interval while waiting for the Active
    Directory Certificate Service Certificate Authority.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $CAServerFQDN,

        [parameter(Mandatory = $true)]
        [System.String]
        $CARootName,

        [Parameter()]
        [System.UInt32]
        $RetryIntervalSec = 10,

        [Parameter()]
        [System.UInt32]
        $RetryCount = 60
    )

    $ca = "$CAServerFQDN\$CARootName"

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($localizedData.CheckingForCAStatusMessage -f $ca)
        ) -join '' )

    $caFound = $false

    for ($count = 0; $count -lt $RetryCount; $count++)
    {
        if (Test-CertificateAuthority `
                -CAServerFQDN $CAServerFQDN `
                -CARootName $CARootName)
        {
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($localizedData.CAFoundMessage -f $ca)
                ) -join '' )

            $caFound = $true
            break
        }
        else
        {
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($localizedData.CANotFoundRetryingMessage -f $ca,$RetryIntervalSec)
                ) -join '' )

            Start-Sleep -Seconds $RetryIntervalSec
        } # if
    } # for

    if (-not $caFound)
    {
        New-InvalidOperationException `
            -Message $($localizedData.CANotFoundAfterError -f $ca,$RetryCount)
    } # if
} # function Set-TargetResource

<#
    .SYNOPSIS
    Waits for the Active Directory Certificate Service Certificate Authority to
    become available or times out.

    .PARAMETER CAServerFQDN
    The FQDN of the Active Directory Certificate Service Certificate Authority to wait
    for. Leave empty to automatically detect.

    .PARAMETER CARootName
    The name of the Active Directory Certificate Service Certificate Authority to wait
    for. Leave empty to automatically detect.

    .PARAMETER RetryIntervalSec
    Specifies the number of seconds to wait for the Active Directory Certificate
    Service Certificate Authority to become available.

    .PARAMETER RetryCount
    The number of times to loop the retry interval while waiting for the Active
    Directory Certificate Service Certificate Authority.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $CAServerFQDN,

        [parameter(Mandatory = $true)]
        [System.String]
        $CARootName,

        [Parameter()]
        [System.UInt32]
        $RetryIntervalSec = 10,

        [Parameter()]
        [System.UInt32]
        $RetryCount = 60
    )

    $ca = "$CAServerFQDN\$CARootName"

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($localizedData.CheckingForCAStatusMessage -f $ca)
        ) -join '' )

    if (Test-CertificateAuthority `
        -CAServerFQDN $CAServerFQDN `
        -CARootName $CARootName)
    {
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($localizedData.CAOnlineMessage -f $ca)
                ) -join '' )

        return $true
    }

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($localizedData.CAOfflineMessage -f $ca)
        ) -join '' )

    return $false
} # function Test-TargetResource

Export-ModuleMember -Function *-TargetResource
