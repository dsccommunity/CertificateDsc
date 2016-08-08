#Requires -Version 4.0

#region localizeddata
if (Test-Path "${PSScriptRoot}\${PSUICulture}")
{
    Import-LocalizedData `
        -BindingVariable LocalizedData `
        -Filename MSFT_xCertificateImport.strings.psd1 `
        -BaseDirectory "${PSScriptRoot}\${PSUICulture}"
}
else
{
    #fallback to en-US
    Import-LocalizedData `
        -BindingVariable LocalizedData `
        -Filename MSFT_xCertificateImport.strings.psd1 `
        -BaseDirectory "${PSScriptRoot}\en-US"
}
#endregion

# Import the common certificate functions
Import-Module -Name ( Join-Path `
    -Path (Split-Path -Path $PSScriptRoot -Parent) `
    -ChildPath '\MSFT_xCertificateCommon\MSFT_xCertificateCommon.psm1' )

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript( { $_ | Test-Thumbprint } )]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory)]
        [ValidateScript( { $_ | Test-CertificatePath } )]
        [System.String]
        $Path,

        [Parameter(Mandatory)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    $CertificateStore = 'Cert:' |
        Join-Path -ChildPath $Location |
        Join-Path -ChildPath $Store

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.GettingCertificateStatusMessage -f $Thumbprint,$CertificateStore)
        ) -join '' )

    if ((Test-Path $CertificateStore) -eq $false)
    {
        ThrowInvalidArgumentError `
            -ErrorId 'CertificateStoreNotFound' `
            -ErrorMessage ($LocalizedData.CertificateStoreNotFoundError -f $CertificateStore)
    }

    $CheckEnsure = [Bool] (
        $CertificateStore |
        Get-ChildItem |
        Where-Object -FilterScript { $_.Thumbprint -ieq $Thumbprint }
    )
    if ($CheckEnsure)
    {
        $Ensure = 'Present'
    }
    else
    {
        $Ensure = 'Absent'
    }

    @{
        Thumbprint = $Thumbprint
        Path       = $Path
        Location   = $Location
        Store      = $Store
        Ensure     = $Ensure
    }
} # end function Get-TargetResource

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript( { $_ | Test-Thumbprint } )]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory)]
        [ValidateScript( { $_ | Test-CertificatePath } )]
        [System.String]
        $Path,

        [Parameter(Mandatory)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    $result = @(Get-TargetResource @PSBoundParameters)

    $CertificateStore = 'Cert:' |
        Join-Path -ChildPath $Location |
        Join-Path -ChildPath $Store

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.TestingCertificateStatusMessage -f $Thumbprint,$CertificateStore)
        ) -join '' )


    if ($Ensure -ne $result.Ensure)
    {
        return $false
    }
    return $true
} # end function Test-TargetResource

function Set-TargetResource
{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateScript( { $_ | Test-Thumbprint } )]
        [System.String]
        $Thumbprint,

        [Parameter(Mandatory)]
        [ValidateScript( { $_ | Test-CertificatePath } )]
        [System.String]
        $Path,

        [Parameter(Mandatory)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [System.String]
        $Location,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Store,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    $CertificateStore = 'Cert:' |
        Join-Path -ChildPath $Location |
        Join-Path -ChildPath $Store

    Write-Verbose -Message ( @(
            "$($MyInvocation.MyCommand): "
            $($LocalizedData.SettingCertificateStatusMessage -f $Thumbprint,$CertificateStore)
        ) -join '' )

    if ($Ensure -ieq 'Present')
    {
        if ($PSCmdlet.ShouldProcess(($LocalizedData.ImportingCertificateShould `
            -f $Path,$CertificateStore)))
        {
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($LocalizedData.ImportingCertficateMessage -f $Path,$CertificateStore)
                ) -join '' )

            $param = @{
                CertStoreLocation = $CertificateStore
                FilePath          = $Path
                Verbose           = $VerbosePreference
            }

            Import-Certificate @param
        }
    }
    elseif ($Ensure -ieq 'Absent')
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.RemovingCertficateMessage -f $Thumbprint,$CertificateStore)
            ) -join '' )

        Get-ChildItem -Path $CertificateStore |
            Where-Object { $_.Thumbprint -ieq $thumbprint } |
            Remove-Item -Force
    }
}  # end function Test-TargetResource

Export-ModuleMember -Function *-TargetResource
