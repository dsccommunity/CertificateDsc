#Requires -Version 4.0

#region localizeddata
if (Test-Path "${PSScriptRoot}\${PSUICulture}")
{
    Import-LocalizedData `
        -BindingVariable LocalizedData `
        -Filename MSFT_xPfxImport.strings.psd1 `
        -BaseDirectory "${PSScriptRoot}\${PSUICulture}"
}
else
{
    #fallback to en-US
    Import-LocalizedData `
        -BindingVariable LocalizedData `
        -Filename MSFT_xPfxImport.strings.psd1 `
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
        [Boolean]
        $Exportable = $false,

        [Parameter()]
        [PSCredential]
        $Credential,

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
            $($LocalizedData.GettingPfxStatusMessage -f $Thumbprint,$CertificateStore)
        ) -join '' )

    if ((Test-Path $CertificateStore) -eq $false)
    {
        ThrowInvalidArgumentError `
            -ErrorId 'CertificateStoreNotFound' `
            -ErrorMessage ($LocalizedData.CertificateStoreNotFoundError -f $CertificateStore)
    }

    $CheckEnsure = [Bool](
        $CertificateStore |
        Get-ChildItem |
        Where-Object -FilterScript {$_.Thumbprint -ieq $Thumbprint}
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
        Exportable = $Exportable
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
        [Boolean]
        $Exportable = $false,

        [Parameter()]
        [PSCredential]
        $Credential,

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
            $($LocalizedData.TestingPfxStatusMessage -f $Thumbprint,$CertificateStore)
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
        [Boolean]
        $Exportable = $false,

        [Parameter()]
        [PSCredential]
        $Credential,

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
            $($LocalizedData.SettingPfxStatusMessage -f $Thumbprint,$CertificateStore)
        ) -join '' )

    if ($Ensure -ieq 'Present')
    {
        if ($PSCmdlet.ShouldProcess(($LocalizedData.ImportingPfxShould `
            -f $Path,$CertificateStore)))
        {
            Write-Verbose -Message ( @(
                    "$($MyInvocation.MyCommand): "
                    $($LocalizedData.ImportingPfxMessage -f $Path,$CertificateStore)
                ) -join '' )

            $param = @{
                Exportable        = $Exportable
                CertStoreLocation = $CertificateStore
                FilePath          = $Path
            }
            if ($Credential)
            {
                $param['Password'] = $Credential.Password
            }
            Import-PfxCertificate @param
        }
    }
    elseif ($Ensure -ieq 'Absent')
    {
        Write-Verbose -Message ( @(
                "$($MyInvocation.MyCommand): "
                $($LocalizedData.RemovingPfxMessage -f $Thumbprint,$CertificateStore)
            ) -join '' )

        Get-ChildItem -Path $CertificateStore |
            Where-Object { $_.Thumbprint -ieq $thumbprint } |
            Remove-Item -Force
    }
} # end function Set-TargetResource

Export-ModuleMember -Function *-TargetResource
